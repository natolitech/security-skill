import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { requireAuth } from './auth.js';

const upload = multer({ dest: 'uploads/' });

export function registerUploadRoutes(app) {
  app.post('/api/uploads/avatar', requireAuth, upload.single('avatar'), (req, res) => {
    const ext = path.extname(req.file.originalname);
    const target = `uploads/${req.user.sub}${ext}`;
    fs.renameSync(req.file.path, target);
    res.json({ url: `/uploads/${req.user.sub}${ext}` });
  });

  app.get('/api/downloads/:filename', requireAuth, (req, res) => {
    res.sendFile(path.resolve(`uploads/${req.params.filename}`));
  });
}
