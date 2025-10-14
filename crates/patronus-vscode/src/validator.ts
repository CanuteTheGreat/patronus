import * as yaml from 'js-yaml';
import { PatronusClient } from './client';

export class ConfigValidator {
    constructor(private client: PatronusClient) {}

    async validate(content: string): Promise<string[]> {
        const errors: string[] = [];

        // Basic YAML syntax check
        try {
            const config = yaml.load(content) as any;

            // Validate structure
            if (!config.apiVersion) {
                errors.push('Missing apiVersion field');
            }

            if (!config.kind) {
                errors.push('Missing kind field');
            }

            if (!config.metadata || !config.metadata.name) {
                errors.push('Missing metadata.name field');
            }

            // Validate specific kinds
            if (config.kind === 'Site') {
                if (!config.spec || !config.spec.location) {
                    errors.push('Site requires spec.location');
                }
            } else if (config.kind === 'Tunnel') {
                if (!config.spec || !config.spec.source || !config.spec.destination) {
                    errors.push('Tunnel requires spec.source and spec.destination');
                }
            } else if (config.kind === 'Policy') {
                if (!config.spec || !config.spec.rules) {
                    errors.push('Policy requires spec.rules');
                }
            }

            // Call API for additional validation
            const apiErrors = await this.client.validateConfig(content);
            errors.push(...apiErrors);

        } catch (e) {
            if (e instanceof Error) {
                errors.push(`YAML syntax error: ${e.message}`);
            } else {
                errors.push('YAML syntax error');
            }
        }

        return errors;
    }

    validateSiteConfig(config: any): string[] {
        const errors: string[] = [];

        if (!config.spec) {
            errors.push('Missing spec');
            return errors;
        }

        if (!config.spec.location) {
            errors.push('Missing spec.location');
        }

        if (config.spec.tunnels && !Array.isArray(config.spec.tunnels)) {
            errors.push('spec.tunnels must be an array');
        }

        return errors;
    }

    validateTunnelConfig(config: any): string[] {
        const errors: string[] = [];

        if (!config.spec) {
            errors.push('Missing spec');
            return errors;
        }

        if (!config.spec.source) {
            errors.push('Missing spec.source');
        }

        if (!config.spec.destination) {
            errors.push('Missing spec.destination');
        }

        if (config.spec.protocol && !['wireguard', 'ipsec', 'gre'].includes(config.spec.protocol)) {
            errors.push('Invalid protocol (must be wireguard, ipsec, or gre)');
        }

        return errors;
    }

    validatePolicyConfig(config: any): string[] {
        const errors: string[] = [];

        if (!config.spec) {
            errors.push('Missing spec');
            return errors;
        }

        if (!config.spec.rules || !Array.isArray(config.spec.rules)) {
            errors.push('Missing or invalid spec.rules');
        }

        return errors;
    }
}
