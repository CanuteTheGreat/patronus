export interface StatusData {
    healthy: boolean;
    sites: number;
    tunnels: number;
    version: string;
    uptime?: number;
}

export class StatusProvider {
    constructor() {}

    formatStatus(status: StatusData): string {
        const lines: string[] = [];

        lines.push('Patronus SD-WAN Status');
        lines.push('=====================');
        lines.push('');
        lines.push(`Status: ${status.healthy ? '✓ Healthy' : '✗ Unhealthy'}`);
        lines.push(`Sites: ${status.sites}`);
        lines.push(`Tunnels: ${status.tunnels}`);
        lines.push(`Version: ${status.version}`);

        if (status.uptime) {
            lines.push(`Uptime: ${this.formatUptime(status.uptime)}`);
        }

        return lines.join('\n');
    }

    private formatUptime(seconds: number): string {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        const parts: string[] = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);

        return parts.join(' ') || '< 1m';
    }

    getStatusIcon(healthy: boolean): string {
        return healthy ? '$(check)' : '$(error)';
    }

    getStatusColor(healthy: boolean): string {
        return healthy ? '#00ff00' : '#ff0000';
    }
}
