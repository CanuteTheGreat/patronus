import * as vscode from 'vscode';
import { PatronusClient } from './client';
import { ConfigValidator } from './validator';
import { StatusProvider } from './status';

let client: PatronusClient;
let validator: ConfigValidator;
let statusBar: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
    console.log('Patronus SD-WAN extension activated');

    // Initialize client
    const config = vscode.workspace.getConfiguration('patronus');
    const apiEndpoint = config.get<string>('apiEndpoint', 'http://localhost:8080');
    client = new PatronusClient(apiEndpoint);
    validator = new ConfigValidator(client);

    // Create status bar item
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(cloud) Patronus';
    statusBar.command = 'patronus.showStatus';
    statusBar.show();
    context.subscriptions.push(statusBar);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('patronus.deployConfig', async () => {
            await deployConfiguration();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('patronus.validateConfig', async () => {
            await validateConfiguration();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('patronus.showStatus', async () => {
            await showStatus();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('patronus.createSite', async () => {
            await createSite();
        })
    );

    // Auto-validate on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            const autoValidate = config.get<boolean>('autoValidate', true);
            if (autoValidate && isPatronusConfig(document)) {
                await validateConfiguration();
            }
        })
    );
}

function isPatronusConfig(document: vscode.TextDocument): boolean {
    return document.fileName.endsWith('.patronus.yaml') ||
           document.fileName.endsWith('.patronus.yml');
}

async function deployConfiguration() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }

    const document = editor.document;
    if (!isPatronusConfig(document)) {
        vscode.window.showWarningMessage('Not a Patronus configuration file');
        return;
    }

    try {
        statusBar.text = '$(sync~spin) Deploying...';
        const content = document.getText();
        await client.deployConfig(content);
        statusBar.text = '$(check) Deployed';
        vscode.window.showInformationMessage('Configuration deployed successfully');
        setTimeout(() => {
            statusBar.text = '$(cloud) Patronus';
        }, 3000);
    } catch (error) {
        statusBar.text = '$(error) Deploy Failed';
        vscode.window.showErrorMessage(`Deployment failed: ${error}`);
        setTimeout(() => {
            statusBar.text = '$(cloud) Patronus';
        }, 3000);
    }
}

async function validateConfiguration() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }

    const document = editor.document;
    if (!isPatronusConfig(document)) {
        return;
    }

    try {
        const content = document.getText();
        const errors = await validator.validate(content);

        if (errors.length === 0) {
            vscode.window.showInformationMessage('Configuration is valid');
        } else {
            const errorMsg = errors.join(', ');
            vscode.window.showWarningMessage(`Validation errors: ${errorMsg}`);
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Validation failed: ${error}`);
    }
}

async function showStatus() {
    try {
        const status = await client.getStatus();
        const panel = vscode.window.createWebviewPanel(
            'patronusStatus',
            'Patronus Status',
            vscode.ViewColumn.One,
            {}
        );

        panel.webview.html = getStatusHtml(status);
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to get status: ${error}`);
    }
}

async function createSite() {
    const siteName = await vscode.window.showInputBox({
        prompt: 'Enter site name',
        placeHolder: 'site-hq'
    });

    if (!siteName) {
        return;
    }

    const siteLocation = await vscode.window.showInputBox({
        prompt: 'Enter site location',
        placeHolder: 'New York'
    });

    if (!siteLocation) {
        return;
    }

    const config = `
apiVersion: v1
kind: Site
metadata:
  name: ${siteName}
spec:
  location: ${siteLocation}
  tunnels: []
  policies: []
`;

    const doc = await vscode.workspace.openTextDocument({
        content: config,
        language: 'yaml'
    });

    await vscode.window.showTextDocument(doc);
}

function getStatusHtml(status: any): string {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Patronus Status</title>
            <style>
                body { font-family: sans-serif; padding: 20px; }
                .status-item { margin: 10px 0; }
                .label { font-weight: bold; }
                .healthy { color: green; }
                .unhealthy { color: red; }
            </style>
        </head>
        <body>
            <h1>Patronus SD-WAN Status</h1>
            <div class="status-item">
                <span class="label">Status:</span>
                <span class="${status.healthy ? 'healthy' : 'unhealthy'}">
                    ${status.healthy ? 'Healthy' : 'Unhealthy'}
                </span>
            </div>
            <div class="status-item">
                <span class="label">Sites:</span> ${status.sites || 0}
            </div>
            <div class="status-item">
                <span class="label">Tunnels:</span> ${status.tunnels || 0}
            </div>
            <div class="status-item">
                <span class="label">Version:</span> ${status.version || 'Unknown'}
            </div>
        </body>
        </html>
    `;
}

export function deactivate() {
    console.log('Patronus SD-WAN extension deactivated');
}
