# Conformance Tests

1. Go to the OpenID Foundation conformance suite website:

  <https://demo.certification.openid.net/>

2. Create a new test plan.
3. Check the "Show early version tests" box.
4. Select an OID4VCI wallet test plan.
5. Use the following test parameters:

  | Parameter                          | Value                     |
  |------------------------------------|---------------------------|
  | Client Authentication Type         | `client_attestation`     |
  | Sender Constraining                | `dpop`                   |
  | Authorization Code Flow Variant    | `issuer_initiated`       |
  | Credential Format                  | any value                |
  | Authorization Request Type         | `simple`                 |
  | Credential Issuer Mode             | any value, but `immediate` is simpler |
  | VCI Profile                        | `haip`                   |
  | Request Method                     | `unsigned`               |
  | Grant Type                         | any value, but `pre_authorization_code` is simpler |
  | Credential Offer Variant           | any value                |
  | Credential Response Encryption     | `plain`                  |

6. Run the test `setup.sh` script.
  This will generate all the necessary
  cryptographic material, as well as a `test.json` file
  containing the conformance test configuration.
  
  ```bash
  examples/conformance/setup.sh
  ```
7. Copy the content of the generated `test.json` file to the `JSON` tab in the "Configure Test" section.
8. Click on "Create Test Plan"
9. Run the test, starting the OID4VCI example client with the following options:
  ```bash
  cargo run --example client -- -t examples/conformance/crypto/attester/jwk.json -k examples/conformance/crypto/wallet/jwk.json
  ```