use std::future::Future;

use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::{Deserialize, Serialize};

use crate::{
    batch::response::BatchResponse,
    profiles::CredentialRequestProfile,
    proof_of_possession::Proof,
    request::{Request, RequestError},
    types::BatchCredentialUrl,
    util::http::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchRequest<CR>
where
    CR: CredentialRequestProfile,
{
    #[serde(bound = "CR: CredentialRequestProfile")]
    credential_requests: Vec<Request<CR>>,
}

impl<CR> BatchRequest<CR>
where
    CR: CredentialRequestProfile,
{
    pub fn new(credential_requests: Vec<Request<CR>>) -> Self {
        Self {
            credential_requests,
        }
    }
}

pub struct BatchRequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    body: BatchRequest<CR>,
    url: BatchCredentialUrl,
    access_token: AccessToken,
}

impl<CR> BatchRequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    pub(crate) fn new(
        body: BatchRequest<CR>,
        url: BatchCredentialUrl,
        access_token: AccessToken,
    ) -> Self {
        Self {
            body,
            url,
            access_token,
        }
    }

    pub fn set_proofs<RE>(
        mut self,
        proofs_of_possession: Vec<Proof>,
    ) -> Result<Self, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        let req_count = self.body.credential_requests.len();
        let pop_count = proofs_of_possession.len();
        if req_count != pop_count {
            return Err(RequestError::Other(format!(
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
    ) -> Result<BatchResponse<CR::Response>, RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<
            BatchResponse<CR::Response>,
            RequestError<<C as AsyncHttpClient<'c>>::Error>,
        >,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    RequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(RequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(serde_json::to_vec(&self.body).map_err(|e| RequestError::Other(e.to_string()))?)
            .map_err(RequestError::Request)
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<BatchResponse<CR::Response>, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
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
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
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

    #[test]
    fn example_batch_request() {
        let _: crate::profiles::core::credential::BatchRequest = serde_json::from_value(json!({
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
