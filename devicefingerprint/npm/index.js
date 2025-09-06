const { spawn } = require('child_process');
const path = require('path');

class DeviceFingerprint {
    constructor() {
        this.pythonCommand = process.platform === 'win32' ? 'python' : 'python3';
    }

    /**
     * Generate device fingerprint using Python backend
     * @param {Object} options - Configuration options
     * @returns {Promise<Object>} Device fingerprint data
     */
    async generateFingerprint(options = {}) {
        return new Promise((resolve, reject) => {
            const pythonScript = `
import json
from devicefingerprint import generate_device_fingerprint
result = generate_device_fingerprint()
print(json.dumps(result, indent=2))
`;

            const python = spawn(this.pythonCommand, ['-c', pythonScript]);
            let output = '';
            let error = '';

            python.stdout.on('data', (data) => {
                output += data.toString();
            });

            python.stderr.on('data', (data) => {
                error += data.toString();
            });

            python.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = JSON.parse(output);
                        resolve(result);
                    } catch (parseError) {
                        reject(new Error(`Failed to parse output: ${parseError.message}`));
                    }
                } else {
                    reject(new Error(`Python process failed: ${error}`));
                }
            });
        });
    }

    /**
     * Validate device fingerprint
     * @param {Object} fingerprint - Fingerprint to validate
     * @returns {Promise<boolean>} Validation result
     */
    async validateFingerprint(fingerprint) {
        if (!fingerprint || typeof fingerprint !== 'object') {
            return false;
        }

        const requiredFields = ['device_id', 'os_info', 'hardware_info'];
        return requiredFields.every(field => fingerprint.hasOwnProperty(field));
    }
}

module.exports = DeviceFingerprint;
