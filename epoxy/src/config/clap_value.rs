//! Workaround for clap + figment config stack.
//! Without this, `default_value_t` ends up overriding values from TOML config.
//! But if we don't use `default_value_t` altogether, user won't see the defaults in `--help`.

use std::{fmt, str::FromStr};

use clap::{CommandFactory, FromArgMatches, ValueEnum};
use serde::ser;

#[derive(Debug, Clone)]
pub enum ValueOrigin {
    Default,
    UserProvided,
}

#[derive(Debug, Clone)]
pub struct ClapValue<V> {
    origin: ValueOrigin,
    value: V,
}

impl<V> ClapValue<V> {
    pub fn default(value: V) -> Self {
        ClapValue {
            origin: ValueOrigin::Default,
            value,
        }
    }

    fn user_provided(value: V) -> Self {
        ClapValue {
            origin: ValueOrigin::UserProvided,
            value,
        }
    }

    fn provide<R>(&mut self, f: impl Fn(&mut V) -> R) -> R {
        self.origin = ValueOrigin::UserProvided;
        f(&mut self.value)
    }
}

impl<V: FromArgMatches> FromArgMatches for ClapValue<V> {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        Ok(ClapValue::user_provided(V::from_arg_matches(matches)?))
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        self.provide(|value| value.update_from_arg_matches(matches))
    }
}

impl<V: CommandFactory> CommandFactory for ClapValue<V> {
    fn command() -> clap::Command {
        V::command()
    }

    fn command_for_update() -> clap::Command {
        V::command_for_update()
    }
}

impl<V: FromStr> FromStr for ClapValue<V> {
    type Err = V::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ClapValue::user_provided(FromStr::from_str(s)?))
    }
}

impl<V: ValueEnum> ValueEnum for ClapValue<V> {
    fn value_variants<'a>() -> &'a [Self] {
        let variants = V::value_variants()
            .iter()
            .map(|value| ClapValue::user_provided(value.clone()))
            .collect::<Vec<_>>();
        variants.leak()
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        self.value.to_possible_value()
    }
}

impl<V: fmt::Display> fmt::Display for ClapValue<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        V::fmt(&self.value, f)
    }
}

/// Only serialize user-provided values
impl<V: ser::Serialize> ser::Serialize for ClapValue<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let option = match self.origin {
            ValueOrigin::Default => None,
            ValueOrigin::UserProvided => Some(&self.value),
        };
        option.serialize(serializer)
    }
}
