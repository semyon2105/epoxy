use serde::Deserialize;
use serde_with::base64::{Base64, Standard};
use serde_with::formats::Unpadded;
use serde_with::{DisplayFromStr, serde_as};

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "input")]
pub enum Request {
    #[serde(rename = "GET_INFO")]
    GetInfo(GetInfo),
    #[serde(rename = "GET_PROVIDERS")]
    GetProviders,
    #[serde(rename = "GET_TERMINALS")]
    #[allow(unused)]
    GetTerminals(GetTerminals),
    #[serde(rename = "GET_CERTIFICATES")]
    GetCertificates(GetCertificates),
    #[serde(rename = "GET_SIGNED_XML")]
    GetSignedXml(GetSignedXml),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInfo {
    pub sb_session: String,
    #[allow(unused)]
    pub host: String,
    #[allow(unused)]
    pub language: String,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTerminals {
    #[allow(unused)]
    pub provider_id: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCertificates {
    pub terminal_id: usize,
    #[allow(unused)]
    #[serde(skip)]
    pub pin: String,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSignedXml {
    pub certificate: Certificate,
    #[allow(unused)]
    #[serde(skip)]
    pub pin: String,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub xml: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    #[serde_as(as = "DisplayFromStr")]
    pub alias: usize,
    #[allow(unused)]
    #[serde(skip)]
    pub name: String,
}
