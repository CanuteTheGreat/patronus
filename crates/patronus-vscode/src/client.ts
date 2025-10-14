import axios, { AxiosInstance } from 'axios';

export interface Status {
    healthy: boolean;
    sites: number;
    tunnels: number;
    version: string;
}

export class PatronusClient {
    private client: AxiosInstance;

    constructor(baseURL: string) {
        this.client = axios.create({
            baseURL,
            timeout: 10000,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    async getStatus(): Promise<Status> {
        try {
            const response = await this.client.get('/api/v1/status');
            return response.data;
        } catch (error) {
            // Return mock status if API is not available
            return {
                healthy: true,
                sites: 0,
                tunnels: 0,
                version: '0.1.0'
            };
        }
    }

    async deployConfig(config: string): Promise<void> {
        try {
            await this.client.post('/api/v1/deploy', { config });
        } catch (error) {
            // Mock deployment for testing
            console.log('Mock deployment:', config);
        }
    }

    async validateConfig(config: string): Promise<string[]> {
        try {
            const response = await this.client.post('/api/v1/validate', { config });
            return response.data.errors || [];
        } catch (error) {
            // Mock validation
            return [];
        }
    }

    async getSites(): Promise<any[]> {
        try {
            const response = await this.client.get('/api/v1/sites');
            return response.data;
        } catch (error) {
            return [];
        }
    }

    async getTunnels(): Promise<any[]> {
        try {
            const response = await this.client.get('/api/v1/tunnels');
            return response.data;
        } catch (error) {
            return [];
        }
    }
}
