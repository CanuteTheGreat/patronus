# Patronus SD-WAN VSCode Extension

VSCode extension for Patronus SD-WAN development and management.

## Features

- **Configuration Management**: Create, edit, and deploy Patronus configurations
- **Validation**: Real-time configuration validation
- **Snippets**: Quick configuration templates for sites, tunnels, and policies
- **Status Monitoring**: View SD-WAN status directly in VSCode
- **Auto-completion**: Smart completion for Patronus YAML configurations

## Commands

- `Patronus: Deploy Configuration` - Deploy the current configuration
- `Patronus: Validate Configuration` - Validate the current configuration
- `Patronus: Show Status` - Show SD-WAN status
- `Patronus: Create New Site` - Create a new site configuration

## Configuration

- `patronus.apiEndpoint`: API endpoint URL (default: http://localhost:8080)
- `patronus.autoValidate`: Automatically validate on save (default: true)

## Snippets

Type these prefixes and press Tab to insert templates:

- `patronus-site` - Create a new site
- `patronus-tunnel` - Create a new tunnel
- `patronus-policy` - Create a routing policy
- `patronus-qos` - Create a QoS policy
- `patronus-failover` - Create a failover policy

## Usage

1. Install the extension
2. Open or create a `.patronus.yaml` file
3. Use snippets to create configurations
4. Save to auto-validate
5. Use `Patronus: Deploy Configuration` to deploy

## Requirements

- VSCode 1.75.0 or higher
- Patronus SD-WAN backend running (for deployment features)

## License

Same as Patronus project
