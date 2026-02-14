use serde::Serialize;
use serde_repr::Serialize_repr;
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::serde_as;

#[derive(Debug, Serialize)]
#[serde(tag = "operation")]
pub enum Response {
    #[serde(rename = "ON_OPEN_EVENT")]
    OnOpenEvent(SuccessResponse<OnOpenEvent>),
    #[serde(rename = "GET_INFO")]
    GetInfo(ResultResponse<GetInfo, GetInfoErrorCode>),
    #[serde(rename = "GET_PROVIDERS")]
    GetProviders(ResultResponse<GetProviders, GetProvidersErrorCode>),
    #[serde(rename = "GET_TERMINALS")]
    GetTerminals(ResultResponse<GetTerminals, GetTerminalsErrorCode>),
    #[serde(rename = "GET_CERTIFICATES")]
    GetCertificates(ResultResponse<GetCertificates, GetCertificatesErrorCode>),
    #[serde(rename = "GET_SIGNED_XML")]
    GetSignedXml(ResultResponse<GetSignedXml, GetSignedXmlErrorCode>),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResultResponse<T, S> {
    Success(SuccessResponse<T>),
    Error(ErrorResponse<S>),
}

impl<T, S> ResultResponse<T, S> {
    pub fn success(payload: T) -> Self {
        ResultResponse::Success(SuccessResponse::new(payload))
    }

    pub fn error(status: S) -> Self {
        ResultResponse::Error(ErrorResponse::new(status))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResponse<T> {
    status: i32,
    payload: T,
}

impl<T> SuccessResponse<T> {
    pub fn new(payload: T) -> Self {
        Self { status: 0, payload }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse<S> {
    status: S,
}

impl<S> ErrorResponse<S> {
    pub fn new(status: S) -> Self {
        Self { status }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnOpenEvent {
    pub app_name: String,
    pub app_version: String,
    pub app_build: i32,
    pub os_name: String,
    pub os_version: String,
    pub os_arch: String,
}

impl OnOpenEvent {
    pub fn with_mocked_info() -> Self {
        Self {
            app_name: "SmartBox".into(),
            app_version: "2.0.0".into(),
            app_build: 1,
            os_name: "".into(),
            os_version: "".into(),
            os_arch: "".into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum GetInfoErrorCode {
    GenericError = 1100,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetProviders {
    pub providers: Vec<Provider>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum GetProvidersErrorCode {
    GenericError = 1200,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTerminals {
    pub terminals: Vec<Terminal>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Terminal {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum GetTerminalsErrorCode {
    GenericError = 1300,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCertificates {
    pub certificates: Vec<Certificate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub alias: String,
    pub name: String,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum GetCertificatesErrorCode {
    GenericError = 1400,
}

#[serde_as]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSignedXml {
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub xml: Vec<u8>,
}

#[derive(Debug, Serialize_repr)]
#[repr(i32)]
pub enum GetSignedXmlErrorCode {
    GenericError = 1500,
}
