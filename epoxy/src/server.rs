use anyhow::{Context, Error, Result, anyhow};
use futures::{SinkExt, StreamExt, TryStreamExt, future};
use libxml::{
    parser::{Parser, ParserOptions, XmlParseError},
    tree::Document,
};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};
use tungstenite::{Message, Utf8Bytes};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    nss::{Nss, PinContext, PinInfo, PinPrompt, SecItem, TokenUri},
    proto::{
        requests::{self, Request},
        responses::{self, Response, ResultResponse, SuccessResponse},
    },
    xmlsec::{XmlSec, XmlSigner},
};

impl TryFrom<Response> for Message {
    type Error = Error;

    fn try_from(response: Response) -> Result<Message> {
        let text = Utf8Bytes::from(
            serde_json::to_string(&response).context("failed to serialize response")?,
        );
        debug!("response: {}", text);

        let message = Message::Text(text);
        Ok(message)
    }
}

impl TryFrom<Message> for Request {
    type Error = Error;

    fn try_from(request: Message) -> Result<Request> {
        let text = request
            .into_text()
            .context("failed to convert WebSocket message to text")?;
        debug!("request: {}", text);

        let request =
            serde_json::from_slice(text.as_bytes()).context("failed to deserialize request")?;
        Ok(request)
    }
}

#[derive(Debug, Default)]
pub struct Session {
    terminals: Vec<TokenUri>,
    certs: Vec<(TokenUri, SecItem, String)>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub allow_soft_tokens: bool,
}

pub struct Server {
    config: ServerConfig,
    pin_prompt: Box<dyn PinPrompt>,
    nss: Nss,
    xml_parser: Parser,
    xmlsec: XmlSec,
}

impl Server {
    pub fn new(
        config: ServerConfig,
        pin_prompt: Box<dyn PinPrompt>,
        nss: Nss,
        xmlsec: XmlSec,
    ) -> Server {
        Server {
            config,
            pin_prompt,
            nss,
            xml_parser: Parser::default(),
            xmlsec,
        }
    }

    pub async fn run(&self, ws_stream: WebSocketStream<TcpStream>) -> Result<()> {
        let (tx, rx) = ws_stream.split();

        let mut tx = Box::pin(tx.with(|response| future::ready(Message::try_from(response))));
        let mut rx = Box::pin(
            rx.try_take_while(|message| future::ok(!message.is_close()))
                .map_err(|e| Error::new(e).context("WebSocket connection error"))
                .and_then(|message| future::ready(Request::try_from(message))),
        );

        let session = self
            .handshake(&mut tx, &mut rx)
            .await
            .context("protocol handshake failed")?;

        self.handle_requests(tx, rx, session)
            .await
            .context("request handler failed")
    }

    async fn handshake(
        &self,
        mut tx: impl SinkExt<Response, Error = Error> + Unpin,
        mut rx: impl TryStreamExt<Ok = Request, Error = Error> + Unpin,
    ) -> Result<Session> {
        let on_open_event = SuccessResponse::new(responses::OnOpenEvent::with_mocked_info());
        tx.send(Response::OnOpenEvent(on_open_event)).await?;

        let Some(first_req) = rx.try_next().await? else {
            return Err(anyhow!("connection closed before protocol handshake"));
        };

        let Request::GetInfo(get_info_req) = first_req else {
            return Err(anyhow!("first request must be GET_INFO"));
        };

        if get_info_req.sb_session.is_empty() {
            return Err(anyhow!("invalid first GET_INFO request"));
        }

        tx.send(Response::GetInfo(self.get_info())).await?;

        Ok(Session::default())
    }

    async fn handle_requests(
        &self,
        mut tx: impl SinkExt<Response, Error = Error> + Unpin,
        mut rx: impl TryStreamExt<Ok = Request, Error = Error> + Unpin,
        mut session: Session,
    ) -> Result<()> {
        while let Some(request) = rx.try_next().await? {
            let response = match request {
                Request::GetInfo(_) => Response::GetInfo(self.get_info()),
                Request::GetProviders => Response::GetProviders(self.get_providers()),
                Request::GetTerminals(_) => {
                    Response::GetTerminals(self.get_terminals(&mut session))
                }
                Request::GetCertificates(req) => {
                    Response::GetCertificates(self.get_certificates(&mut session, req))
                }
                Request::GetSignedXml(req) => {
                    Response::GetSignedXml(self.get_signed_xml(&session, req))
                }
            };
            tx.send(response).await?;
        }
        Ok(())
    }

    fn get_info(&self) -> ResultResponse<responses::GetInfo, responses::GetInfoErrorCode> {
        ResultResponse::success(responses::GetInfo {
            provider_id: None,
            terminal_id: None,
            certificate_id: None,
        })
    }

    fn get_providers(
        &self,
    ) -> ResultResponse<responses::GetProviders, responses::GetProvidersErrorCode> {
        let providers = vec![responses::Provider {
            id: 0,
            name: String::from("NSS"),
        }];
        ResultResponse::success(responses::GetProviders { providers })
    }

    fn get_terminals(
        &self,
        session: &mut Session,
    ) -> ResultResponse<responses::GetTerminals, responses::GetTerminalsErrorCode> {
        let tokens = self.nss.get_tokens();
        let Some(tokens) = tokens else {
            return ResultResponse::error(responses::GetTerminalsErrorCode::GenericError);
        };

        let valid_tokens = tokens.iter().filter_map(|token| {
            if (self.config.allow_soft_tokens || token.is_hw()) && !token.is_internal() {
                Some((token.uri(), token.name()))
            } else {
                None
            }
        });

        session.terminals.clear();
        let mut terminals = Vec::new();

        for (index, (uri, name)) in valid_tokens.enumerate() {
            session.terminals.push(uri);
            terminals.push(responses::Terminal { id: index, name });
        }

        ResultResponse::success(responses::GetTerminals { terminals })
    }

    fn get_certificates(
        &self,
        session: &mut Session,
        request: requests::GetCertificates,
    ) -> ResultResponse<responses::GetCertificates, responses::GetCertificatesErrorCode> {
        let token_uri = session.terminals.get(request.terminal_id);
        let Some(token_uri) = token_uri else {
            return ResultResponse::error(responses::GetCertificatesErrorCode::GenericError);
        };

        let token = self.nss.get_token(token_uri);
        let Some(token) = token else {
            return ResultResponse::error(responses::GetCertificatesErrorCode::GenericError);
        };

        // here PIN will be requested only if the token doesn't allow passwordless access to certs
        let pin_context = self.get_pin_context(None, String::from("List certificates"));
        let Ok(certs) = self.nss.get_certs_in_token(&pin_context, &token) else {
            warn!("failed to log in to {}", token.name());
            return ResultResponse::error(responses::GetCertificatesErrorCode::GenericError);
        };
        let Some(certs) = certs else {
            return ResultResponse::error(responses::GetCertificatesErrorCode::GenericError);
        };

        let valid_certs = certs.iter().filter_map(|cert| {
            let der = cert.der();

            let (_, x509) = X509Certificate::from_der(der.as_ref()).ok()?;
            let common_name = x509.subject().iter_common_name().next()?;
            let label = common_name.as_str().ok()?.to_owned();

            // keep only signing certs
            let key_usage = x509.key_usage().ok()??.value;
            if !(key_usage.digital_signature() && key_usage.non_repudiation()) {
                return None;
            }

            if !x509.validity().is_valid() {
                warn!("certificate \"{label}\" is either expired or not yet active");
                return None;
            }

            Some((der, label))
        });

        session.certs.clear();
        let mut certificates = Vec::new();

        for (index, (der, label)) in valid_certs.enumerate() {
            session.certs.push((token_uri.clone(), der, label.clone()));
            certificates.push(responses::Certificate {
                alias: index,
                name: label,
            });
        }

        ResultResponse::success(responses::GetCertificates { certificates })
    }

    fn get_signed_xml(
        &self,
        session: &Session,
        request: requests::GetSignedXml,
    ) -> ResultResponse<responses::GetSignedXml, responses::GetSignedXmlErrorCode> {
        let cert = session.certs.get(request.certificate.alias);
        let Some((token_uri, der, cert_label)) = cert else {
            return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
        };

        let Some(token) = self.nss.get_token(token_uri) else {
            return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
        };

        let Ok(mut document) = self.parse_xml(request.xml) else {
            return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
        };

        let reason = match try_identify_form(&document) {
            Some(EporeziFormKind::LoginForm) => String::from("Log in to ePorezi"),
            Some(EporeziFormKind::TaxForm(server_path)) => {
                format!("Sign form {}", server_path)
            }
            None => String::from("Sign form (unidentified)"),
        };

        info!("signature request: {}: {}", cert_label, reason);
        {
            let pin_context = self.get_pin_context(Some(cert_label.clone()), reason);
            let Ok(_logout_guard) = self.nss.authenticate(&pin_context, &token) else {
                warn!("failed to log in to {}", token.name());
                return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
            };

            let Ok(signer) = XmlSigner::with_cert(&self.xmlsec, der) else {
                return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
            };

            let Ok(()) = signer.sign(&mut document) else {
                return ResultResponse::error(responses::GetSignedXmlErrorCode::GenericError);
            };
        }

        let xml = document.to_string().into_bytes();

        ResultResponse::success(responses::GetSignedXml { xml })
    }

    fn get_pin_context(&'_ self, cert: Option<String>, reason: String) -> PinContext<'_> {
        let pin_info = PinInfo { cert, reason };
        PinContext::new(&*self.pin_prompt, pin_info)
    }

    fn parse_xml(&self, xml: Vec<u8>) -> Result<Document, XmlParseError> {
        let opts = ParserOptions {
            recover: false,
            ..Default::default()
        };
        self.xml_parser.parse_string_with_options(xml, opts)
    }
}

enum EporeziFormKind {
    LoginForm,
    TaxForm(String),
}

fn try_identify_form(document: &Document) -> Option<EporeziFormKind> {
    let root = document.get_root_element()?;

    let login_form_nodes = root.findnodes("/*[local-name() = 'envelopaEPrijave']/timestamp");
    if let Ok(nodes) = login_form_nodes
        && nodes.len() == 1
    {
        return Some(EporeziFormKind::LoginForm);
    }

    let tax_form_nodes =
        root.findnodes("/*[local-name() = 'envelopaEPrijave']/deklaracijaZaglavlje/xmlPath");
    if let Ok(nodes) = tax_form_nodes {
        let node = nodes.first()?;
        let server_path = node.get_content();
        if !server_path.is_empty() {
            return Some(EporeziFormKind::TaxForm(server_path));
        }
    }

    None
}
