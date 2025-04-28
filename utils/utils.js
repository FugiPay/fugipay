const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
  const QRCode = require('qrcode');

  const generateQRCode = async (data, fileName) => {
    const qrCodeBuffer = await QRCode.toBuffer(JSON.stringify(data));
    const s3 = new S3Client({ region: process.env.AWS_REGION });
    const uploadParams = {
      Bucket: process.env.S3_BUCKET,
      Key: `qr-codes/${fileName}`,
      Body: qrCodeBuffer,
      ContentType: 'image/png',
    };
    await s3.send(new PutObjectCommand(uploadParams));
    return `https://${process.env.S3_BUCKET}.s3.amazonaws.com/${uploadParams.Key}`;
  };

  module.exports = { generateQRCode };