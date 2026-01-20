use std::{future::Future, marker::PhantomData};

use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    batch::response::BatchCredentialResponse,
    proof_of_possession::Proof,
    request::{
        AnyCredentialRequestParams, CredentialRequest, CredentialRequestError,
        CredentialRequestParams,
    },
    types::BatchCredentialUrl,
    util::http::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(bound = "F: CredentialRequestParams")]
pub struct BatchCredentialRequest<F: CredentialRequestParams = AnyCredentialRequestParams> {
    credential_requests: Vec<CredentialRequest<F>>,
}

impl<F: CredentialRequestParams> BatchCredentialRequest<F> {
    pub fn new(credential_requests: Vec<CredentialRequest<F>>) -> Self {
        Self {
            credential_requests,
        }
    }
}

pub struct BatchCredentialRequestBuilder<F: CredentialRequestParams, T> {
    body: BatchCredentialRequest<F>,
    url: BatchCredentialUrl,
    access_token: AccessToken,
    credential_type: PhantomData<T>,
}

impl<F, T> BatchCredentialRequestBuilder<F, T>
where
    F: CredentialRequestParams,
{
    pub(crate) fn new(
        body: BatchCredentialRequest<F>,
        url: BatchCredentialUrl,
        access_token: AccessToken,
    ) -> Self {
        Self {
            body,
            url,
            access_token,
            credential_type: PhantomData,
        }
    }

    pub fn set_proofs<RE>(
        mut self,
        proofs_of_possession: Vec<Proof>,
    ) -> Result<Self, CredentialRequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        let req_count = self.body.credential_requests.len();
        let pop_count = proofs_of_possession.len();
        if req_count != pop_count {
            return Err(CredentialRequestError::Other(format!(
                "invalid proof count: expected {req_count}; found {pop_count}"
            )));
        }

        for (i, request) in self.body.credential_requests.iter_mut().enumerate() {
            request.proof = Some(proofs_of_possession.get(i).unwrap().to_owned())
        }

        Ok(self)
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<BatchCredentialResponse<T>, CredentialRequestError<C::Error>>
    where
        C: SyncHttpClient,
        T: DeserializeOwned,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                CredentialRequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(CredentialRequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<BatchCredentialResponse<T>, CredentialRequestError<C::Error>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        T: DeserializeOwned,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    CredentialRequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(CredentialRequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, CredentialRequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(
                serde_json::to_vec(&self.body)
                    .map_err(|e| CredentialRequestError::Other(e.to_string()))?,
            )
            .map_err(CredentialRequestError::Request)
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<BatchCredentialResponse<T>, CredentialRequestError<RE>>
    where
        T: DeserializeOwned,
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(CredentialRequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers()
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    http_response.body(),
                ))
                .map_err(CredentialRequestError::Parse)
            }
            ref content_type => Err(CredentialRequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_batch_request() {
        let _: BatchCredentialRequest = serde_json::from_value(json!({
            "credential_requests":[
              {
                 "format":"jwt_vc_json",
                 "credential_definition": {
                   "type":[
                     "VerifiableCredential",
                     "UniversityDegreeCredential"
                   ]
                 },
                 "proof":{
                    "proof_type":"jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZTpl...C_aZKPxgihac0aW9EkL1nOzM"
                 }
              },
              {
                 "format":"mso_mdoc",
                 "doctype":"org.iso.18013.5.1.mDL",
                 "proof":{
                    "proof_type":"jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                 }
              }
           ]
        }))
        .unwrap();
    }
}
