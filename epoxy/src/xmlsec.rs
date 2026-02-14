use std::{
    ffi::CString,
    fmt::Write,
    marker::PhantomData,
    ptr::{null, null_mut},
    rc::Rc,
    sync::{Mutex, MutexGuard},
};

use libxml::tree::Document;
use thiserror::Error;
use x509_parser::{
    asn1_rs::ToDer,
    error::X509Error,
    nom,
    oid_registry::{
        OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_GIVEN_NAME, OID_X509_LOCALITY_NAME,
        OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT, OID_X509_SERIALNUMBER,
        OID_X509_SURNAME,
    },
    prelude::{FromDer, X509Certificate},
    x509::X509Name,
};
use xmlsec_nss_sys::*;

use crate::nss;

static INIT_LOCK: Mutex<()> = Mutex::new(());

type XmlSecInitHandle = ();

pub struct XmlSec<'a> {
    nss: Rc<nss::Nss<'a>>,
    _guard: MutexGuard<'static, ()>,
    _marker: PhantomData<(&'a nss::Nss<'a>, &'a XmlSecInitHandle)>,
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error("cannot create multiple xmlsec contexts")]
    AlreadyInitialized,
    #[error("incompatible xmlsec version")]
    IncompatibleVersion,
    #[error("xmlsec error: {0}")]
    XmlSec(i32),
}

impl<'a> XmlSec<'a> {
    pub fn initialize(nss: Rc<nss::Nss<'a>>) -> Result<XmlSec<'a>, InitError> {
        let Ok(guard) = INIT_LOCK.try_lock() else {
            return Err(InitError::AlreadyInitialized);
        };

        let code = unsafe {
            let abi_compat_mode = xmlSecCheckVersionMode_xmlSecCheckVersionABICompatible;
            xmlSecCheckVersionExt(1, 3, 0, abi_compat_mode)
        };
        if code == 0 {
            return Err(InitError::IncompatibleVersion);
        } else if code < 0 {
            return Err(InitError::XmlSec(code));
        }

        let code = unsafe { xmlSecInit() };
        if code < 0 {
            return Err(InitError::XmlSec(code));
        }

        let code = unsafe { xmlSecNssInit() };
        if code < 0 {
            return Err(InitError::XmlSec(code));
        }

        Ok(XmlSec {
            nss,
            _guard: guard,
            _marker: PhantomData,
        })
    }
}

impl<'a> Drop for XmlSec<'a> {
    fn drop(&mut self) {
        unsafe {
            xmlSecNssShutdown();
            xmlSecShutdown();
        }
    }
}

pub struct XmlSigner<'a> {
    issuer: CString,
    subject: CString,
    serial_number: CString,
    dsig_ptr: xmlSecDSigCtxPtr,
    _logout_guard: nss::LogoutGuard,
    _marker: PhantomData<&'a XmlSec<'a>>,
}

#[derive(Debug, Error)]
pub enum SignerInitError {
    #[error("invalid certificate")]
    Cert(nom::Err<X509Error>),
    #[error("null char in {0}")]
    CertFfi(&'static str),
    #[error("failed to create dsig context")]
    DSigInit,
    #[error("failed to load key")]
    KeyLoad,
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("failed to create template")]
    Template,
    #[error("failed to sign document")]
    Signature,
    #[error("invalid XML document")]
    Document,
}

impl<'a> Drop for XmlSigner<'a> {
    fn drop(&mut self) {
        unsafe {
            xmlSecDSigCtxDestroy(self.dsig_ptr); // frees the xmlsec key as well
        }
    }
}

impl<'a> XmlSigner<'a> {
    pub fn with_cert(
        xmlsec: &'a XmlSec<'a>,
        cert_item: &nss::SecItem,
    ) -> Result<XmlSigner<'a>, SignerInitError> {
        let der = cert_item.as_ref();
        let (_, x509) = X509Certificate::from_der(der).map_err(SignerInitError::Cert)?;

        let issuer = CString::new(format_as_java(&x509.issuer))
            .map_err(|_| SignerInitError::CertFfi("issuer"))?;
        let subject = CString::new(format_as_java(&x509.subject))
            .map_err(|_| SignerInitError::CertFfi("subject"))?;
        let serial_number = CString::new(x509.serial.to_string())
            .map_err(|_| SignerInitError::CertFfi("serial number"))?;

        let dsig_ptr = unsafe { xmlSecDSigCtxCreate(null_mut()) };
        if dsig_ptr.is_null() {
            return Err(SignerInitError::DSigInit);
        }

        let key_ptr = unsafe {
            xmlSecNssAppKeyFromCertLoadSECItem(
                cert_item.as_ptr() as *mut _,
                xmlSecKeyDataFormat_xmlSecKeyDataFormatCertDer,
            )
        };
        if key_ptr.is_null() {
            unsafe { xmlSecDSigCtxDestroy(dsig_ptr) };
            return Err(SignerInitError::KeyLoad);
        };

        unsafe {
            (*dsig_ptr).signKey = key_ptr;
        }

        Ok(XmlSigner {
            issuer,
            subject,
            serial_number,
            dsig_ptr,
            _logout_guard: xmlsec.nss.ensure_token_logout(),
            _marker: PhantomData,
        })
    }

    pub fn sign(&self, document: &mut Document) -> Result<(), SignError> {
        let sig_node = unsafe {
            xmlSecTmplSignatureCreate(
                document.doc_ptr().cast::<xmlDoc>(),
                xmlSecTransformInclC14NGetKlass(),
                xmlSecNssTransformRsaSha256GetKlass(),
                null(),
            )
        };
        if sig_node.is_null() {
            return Err(SignError::Template);
        }

        let reference_node = unsafe {
            xmlSecTmplSignatureAddReference(
                sig_node,
                xmlSecNssTransformSha256GetKlass(),
                null(),
                c"".as_ptr().cast::<u8>(),
                null(),
            )
        };
        if reference_node.is_null() {
            return Err(SignError::Template);
        }

        let transform_node = unsafe {
            xmlSecTmplReferenceAddTransform(reference_node, xmlSecTransformEnvelopedGetKlass())
        };
        if transform_node.is_null() {
            return Err(SignError::Template);
        }

        let key_info_node = unsafe { xmlSecTmplSignatureEnsureKeyInfo(sig_node, null()) };
        if key_info_node.is_null() {
            return Err(SignError::Template);
        }

        let x509_data_node = unsafe { xmlSecTmplKeyInfoAddX509Data(key_info_node) };
        if x509_data_node.is_null() {
            return Err(SignError::Template);
        }

        let x509_cert_node = unsafe { xmlSecTmplX509DataAddCertificate(x509_data_node) };
        if x509_cert_node.is_null() {
            return Err(SignError::Template);
        }

        let x509_issuer_serial_node = unsafe { xmlSecTmplX509DataAddIssuerSerial(x509_data_node) };
        if x509_issuer_serial_node.is_null() {
            return Err(SignError::Template);
        }

        unsafe {
            xmlSecTmplX509IssuerSerialAddIssuerName(
                x509_issuer_serial_node,
                self.issuer.as_ptr().cast::<u8>(),
            )
        };
        unsafe {
            xmlSecTmplX509IssuerSerialAddSerialNumber(
                x509_issuer_serial_node,
                self.serial_number.as_ptr().cast::<u8>(),
            )
        };

        let x509_subject_node = unsafe {
            xmlSecAddChild(
                x509_data_node,
                xmlSecNodeX509SubjectName.as_ptr(),
                xmlSecDSigNs.as_ptr(),
            )
        };
        unsafe { xmlNodeSetContent(x509_subject_node, self.subject.as_ptr().cast::<u8>()) };

        let root_node = &mut document.get_root_element().ok_or(SignError::Document)?;
        unsafe { xmlAddChild(root_node.node_ptr().cast::<_xmlNode>(), sig_node) };

        let code = unsafe { xmlSecDSigCtxSign(self.dsig_ptr, sig_node) };
        if code < 0 {
            return Err(SignError::Signature);
        }

        Ok(())
    }
}

// Tested with MUP cert, might not work on others
fn format_as_java<'a>(x509_name: &X509Name<'a>) -> String {
    let abv_map = [
        (OID_X509_COMMON_NAME, "CN"),
        (OID_X509_ORGANIZATIONAL_UNIT, "OU"),
        (OID_X509_ORGANIZATION_NAME, "O"),
        (OID_X509_LOCALITY_NAME, "L"),
        (OID_X509_COUNTRY_NAME, "C"),
        (OID_X509_GIVEN_NAME, "GIVENNAME"),
        (OID_X509_SURNAME, "SURNAME"),
        (OID_X509_SERIALNUMBER, "SERIALNUMBER"),
    ];

    let mut str = x509_name
        .iter_attributes()
        .fold(String::new(), |mut acc, attr| {
            let oid = attr.attr_type();
            let value = attr.attr_value();

            match abv_map.iter().find(|item| item.0 == *oid) {
                None => {
                    if let Ok(der) = value.to_der_vec() {
                        let _ = write!(acc, "{}=#{},", oid.to_id_string(), hex::encode(der));
                    }
                }
                Some((_, abv)) => {
                    if let Ok(value) = value.as_any_string() {
                        let _ = write!(acc, "{}={},", abv, value);
                    }
                }
            };
            acc
        });

    str.pop(); // pop trailing comma
    str
}
