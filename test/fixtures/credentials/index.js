import fs from 'fs';
import path from 'path';

const credNames = ['idp1', 'sp1', 'sp2'];

export default credNames.reduce((creds, credName) => {
  const crtFileName = path.resolve(__dirname, `${credName}.crt`);
  const keyFileName = path.resolve(__dirname, `${credName}.key`);
  let crtPEM;
  let keyPEM;
  if (fs.existsSync(crtFileName)) {
    crtPEM = fs.readFileSync(crtFileName, 'utf8');
  }
  if (fs.existsSync(keyFileName)) {
    keyPEM = fs.readFileSync(keyFileName, 'utf8');
  }
  creds[credName] = {
    certificate: crtPEM,
    privateKey: keyPEM,
  };
  return creds;
}, {});
