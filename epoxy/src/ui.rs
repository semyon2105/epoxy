use std::cell::RefCell;
use std::rc::Rc;

use gtk4::gio::prelude::*;
use gtk4::glib::{ExitCode, clone};
use gtk4::{
    Application, Box, Button, Label, Orientation, PasswordEntry, Separator, Window, glib,
    prelude::*,
};
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::pin::{PinInfo, PinPrompt};

pub fn run(app_id: &str, pin_rx: mpsc::Receiver<PinChannelMessage>) -> ExitCode {
    let app = Application::builder().application_id(app_id).build();

    let pin_rx_cell = RefCell::new(Some(pin_rx));
    let app_holder = RefCell::new(None);

    app.connect_activate(move |app| {
        let pin_rx = pin_rx_cell.take();
        let Some(mut pin_rx) = pin_rx else {
            error!("failed to establish PIN channel");
            return;
        };

        glib::spawn_future_local(clone!(
            #[weak]
            app,
            async move {
                while let Some((pin_info, token_name, reply)) = pin_rx.recv().await {
                    new_pin_popup(&app, pin_info, token_name, reply)
                }
            }
        ));

        // do not let UI thread exit
        app_holder.replace(Some(app.hold()));

        debug!("UI initialized");
    });

    app.run_with_args(&[] as &[&str])
}

fn new_pin_popup(app: &Application, pin_info: PinInfo, token_name: String, reply: PinReply) {
    let cert_label = pin_info
        .cert
        .map(|cert| Label::builder().label(cert).xalign(0.0).build());

    let reason_label = Label::builder().label(pin_info.reason).xalign(0.0).build();

    let separator = Separator::builder()
        .orientation(Orientation::Horizontal)
        .build();

    let pin_label = Label::builder()
        .label(format!("Enter PIN for {}:", token_name))
        .xalign(0.0)
        .build();

    let pin_entry = PasswordEntry::builder().height_request(48).build();

    let ok_button = Button::builder().label("OK").width_request(108).build();

    let cancel_button = Button::builder().label("Cancel").width_request(108).build();

    let button_box = Box::builder()
        .orientation(Orientation::Horizontal)
        .halign(gtk4::Align::End)
        .spacing(12)
        .build();

    button_box.append(&ok_button);
    button_box.append(&cancel_button);

    let content_box = Box::builder()
        .orientation(Orientation::Vertical)
        .margin_start(12)
        .margin_end(12)
        .margin_top(12)
        .margin_bottom(12)
        .spacing(12)
        .build();

    if let Some(cert_label) = cert_label {
        content_box.append(&cert_label);
    }
    content_box.append(&reason_label);
    content_box.append(&separator);
    content_box.append(&pin_label);
    content_box.append(&pin_entry);
    content_box.append(&button_box);

    let window = Window::builder()
        .application(app)
        .title("epoxy")
        .default_width(720)
        .modal(true)
        .resizable(false)
        .child(&content_box)
        .build();

    let reply_cell = Rc::new(RefCell::new(Some(reply)));
    ok_button.connect_clicked(clone!(
        #[strong]
        reply_cell,
        #[weak]
        window,
        #[weak]
        pin_entry,
        move |_| {
            if let Some(reply) = reply_cell.take() {
                let _result = reply.send(Some(pin_entry.text().into()));
            }
            window.destroy();
        }
    ));
    cancel_button.connect_clicked(clone!(
        #[strong]
        reply_cell,
        #[weak]
        window,
        move |_| {
            if let Some(reply) = reply_cell.take() {
                let _result = reply.send(None);
            }
            window.destroy();
        }
    ));

    window.present();
}

pub type PinReply = oneshot::Sender<Option<String>>;

pub type PinChannelMessage = (PinInfo, String, PinReply);

pub fn new_pin_channel() -> (
    mpsc::Sender<PinChannelMessage>,
    mpsc::Receiver<PinChannelMessage>,
) {
    mpsc::channel(1)
}

impl PinPrompt for mpsc::Sender<PinChannelMessage> {
    fn prompt_pin(&self, pin_info: PinInfo, token_name: String) -> Option<String> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.try_send((pin_info, token_name, reply_tx))
            .map_err(|e| {
                error!("failed to send PIN request to channel: {e}");
            })
            .ok()?;

        reply_rx
            .recv()
            .map_err(|_| {
                debug!("PIN dialog closed");
            })
            .ok()?
    }
}
