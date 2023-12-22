/// This module contains structure and functions to handle the configuration of the application.
/// There are mainly two components:
/// 1. The [`Configuration`] structure that is parsed from a YAML file
/// 2. The [`CommandLineArguments`] that are passed by users as command options
///
/// [`CommandLineArguments`] are used first to get the path to the YAML file.
/// If no path is provided, by default we check the current directory.
/// After this step, we have the YAML configuration provided by the user
/// or the default one.
/// Finally, the remaining [`CommandLineArguments`] are parsed and they
/// eventually overwrite the YAML configuration.
use std::{error::Error, fs::File, io::Read, time::Duration};

use clap::Parser;
use serde::Deserialize;

use super::{DEFAULT_INACTIVITY_TIMEOUT, DEFAULT_IP_ADDRESS};

/// Struct containing the configuration for the Avalanche client
#[derive(Debug, Deserialize, PartialEq)]
pub struct Configuration {
    /// How long the application should stay connected after a successful handshake.
    /// At the moment, this cannot be set from YAML.
    pub connection_duration: Duration,

    /// Destination IP (format is [address]:[port]) of the peer to which we want to connect to.
    pub destination_address: String,

    /// Timeout after which connections are closed if no messages are received.
    pub inactivity_timeout: Duration,

    /// Configuration of the fields included in the Version message sent during the handshake.
    pub version_message: VersionMessage,
}

impl Configuration {
    /// Constructs a new configuration through these steps:
    /// 1. Look at the eventual path provided by the user or look in the default location
    /// 2. Read the configuration from file or, if it does not exist, return the default one
    /// 3. Check the eventual command line arguments and overwrite the configuration with them
    pub fn new() -> Self {
        // Parse the command line arguments
        let args = CommandLineArguments::parse();

        // Check if the user provided a custom config file path or use the default one
        let config_path = args
            .configuration_file_path
            .clone()
            .unwrap_or(String::from("config.yaml"));

        // Read the configuration from file or provide the default one
        let mut configuration = Self::from_config_file(&config_path).unwrap_or_default();

        // Overwrite the configuration with command line arguments eventually available
        configuration.update_from_args(args);

        configuration
    }

    /// Parses the configuration from a YAML file.
    fn from_config_file(config_path: &str) -> Result<Configuration, Box<dyn Error>> {
        let mut file = File::open(config_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        Ok(serde_yaml::from_str(&content)?)
    }

    /// Updates the configuration by overwriting fields found by Clap
    /// as command line arguments.
    fn update_from_args(&mut self, args: CommandLineArguments) {
        // Check the presence of a value for the connetion duration
        if let Some(value) = args.connection_duration {
            self.connection_duration = value;
        }

        // Check the presence of a value for the IP [address]:[port] argument
        if let Some(value) = args.ip_address {
            self.destination_address = value;
        }

        // Check the presence of a value for the inactivity timeout argument
        if let Some(value) = args.timeout {
            self.inactivity_timeout = value;
        }
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            connection_duration: Duration::ZERO,
            destination_address: String::from(DEFAULT_IP_ADDRESS),
            inactivity_timeout: DEFAULT_INACTIVITY_TIMEOUT,
            version_message: VersionMessage {
                network_id: 12345,
                version_string: String::from("avalanche/1.10.17"),
                ip_address: String::from("127.0.0.1"),
                ip_port: 9651,
            },
        }
    }
}

/// Struct containing the configuration for the P2P Version message.
#[derive(Debug, Deserialize, PartialEq)]
pub struct VersionMessage {
    /// ID of the network the client wants to join (e.g. Mainnet, Testnet, etc.).
    pub network_id: u32,

    /// String representing the current version of the client.
    /// It should match the destination peer version, otherwise there is
    /// risk to be rejected by other nodes.
    pub version_string: String,

    /// IP address to be advertised (the local one).
    pub ip_address: String,

    /// Local IP port to be advertised.
    pub ip_port: u32,
}

/// Struct containing the command line arguments supported.
#[derive(Clone, Debug, Default, Parser)]
#[command(author, version, about, long_about = None)]
struct CommandLineArguments {
    /// Path to the YAML configuration file.
    #[arg(short, long)]
    configuration_file_path: Option<String>,

    /// How long the connection should be kept alive after a successful
    /// handshake procedure.
    #[arg(long)]
    #[clap(value_parser = |secs: &str| secs.parse().map(Duration::from_secs))]
    connection_duration: Option<Duration>,

    /// IP address of the destination peer as [ADDRESS]:[PORT].
    #[arg(short, long)]
    ip_address: Option<String>,

    /// Inactivity timeout for P2P communications (seconds).
    #[arg(short, long)]
    #[clap(value_parser = |secs: &str| secs.parse().map(Duration::from_secs))]
    timeout: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CommandLineArguments, Configuration};

    /// Checks that the configuration file read from YAML file is correctly
    /// overwritten with command line arguments.
    #[test]
    fn check_configuration_overwrite() {
        // Get the default configuration
        let default_configuration = Configuration::default();
        let mut configuration = Configuration::default();

        // Empty args
        let mut args = CommandLineArguments::default();

        // The configuration should stay untouched
        configuration.update_from_args(args.clone());
        assert_eq!(default_configuration, configuration);

        // The configuration path should not be taken into account when updating the structure
        args.configuration_file_path = Some(String::from("custom_path"));
        configuration.update_from_args(args.clone());
        assert_eq!(default_configuration, configuration);

        // Let's set the IP address
        args.ip_address = Some(String::from("192.168.0.1"));
        configuration.update_from_args(args.clone());
        assert_ne!(default_configuration, configuration);
        assert_eq!(
            configuration.destination_address,
            args.ip_address.clone().unwrap()
        );

        // Let's set the inactivity timeout
        args.timeout = Some(Duration::from_secs(7));
        configuration.update_from_args(args.clone());
        assert_ne!(default_configuration, configuration);
        assert_eq!(configuration.inactivity_timeout, args.timeout.unwrap());

        // Try to reset the configuration by using the default values
        args.ip_address = Some(default_configuration.destination_address.clone());
        args.timeout = Some(default_configuration.inactivity_timeout);
        configuration.update_from_args(args);
        assert_eq!(default_configuration, configuration);
    }
}
