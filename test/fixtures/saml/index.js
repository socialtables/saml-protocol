import fs from 'fs';
import path from 'path';

export default function get(fixtureName) {
  const resolvedPath = path.resolve(__dirname, fixtureName);
  return fs.readFileSync(resolvedPath, 'utf8');
}
