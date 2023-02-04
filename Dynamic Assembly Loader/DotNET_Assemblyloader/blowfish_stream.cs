using System;
using System.IO;

namespace Blowfish_encryption
{
    public class BlowfishStream : Stream
    {
        public enum Target
        {
            Encrypted,
            Normal
        };

        Stream stream;
        Blowfish bf;
        Target target;

        public BlowfishStream(Stream stream, Blowfish bf, Target target)
        {
            this.stream = stream;
            this.bf = bf;
            this.target = target;
        }

        //Returns true if the stream support reads.
        public override bool CanRead
        {
            get { return stream.CanRead; }
        }

        //Returns true is the stream supports seeks.
        public override bool CanSeek
        {
            get { return stream.CanSeek; }
        }

        /// Returns true if the stream supports writes.
        public override bool CanWrite
        {
            get { return stream.CanWrite; }
        }

        /// Returns the length of the stream.
        public override long Length
        {
            get { return stream.Length; }
        }

        /// Gets or Sets the posistion of the stream.
        public override long Position
        {
            get { return stream.Position; }
            set { stream.Position = value; }
        }

        /// Flushes the stream.
        public override void Flush()
        {
            stream.Flush();
        }

        //Read data from the stream.
        //used when you already have data in stream.
        ///<param name="buffer">The buffer to read into.</param>
        ///<param name="offset">The offset in the buffer to begin storing data.</param>
        ///<param name="count">The number of bytes to read.</param>
        //<returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            int bytesRead = stream.Read(buffer, offset, count);
            if (target == Target.Normal)
            {
                bf.Encipher(buffer, bytesRead);
            }
            else
            {
                bf.Decipher(buffer, bytesRead);
            }
            return bytesRead;
        }

        //Write data to the stream.
        //used when stream is empty and you want to write encrypted data in it.
        ///<param name="buffer">The buffer containing the data to write.</param>
        ///<param name="offset">The offset in the buffer where the data begins.</param>
        ///<param name="count">The number of bytes to write.</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (target == Target.Normal)
            {
                buffer = addPadding(buffer, count);
                count = buffer.Length;
                bf.Encipher(buffer, count);
            }
            else
            {
                bf.Decipher(buffer, count);
                buffer = removePadding(buffer, count);
            }
            stream.Write(buffer, offset, buffer.Length);
        }

        //Move the current stream posistion to the specified location.
        ///<param name="offset">The offset from the origin to seek.</param>
        ///<param name="origin">The origin to seek from.</param>
        ///<returns>The new position.</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            return stream.Seek(offset, origin);
        }

        //Set the stream length.
        ///<param name="value">The length to set.</param>
        public override void SetLength(long value)
        {
            stream.SetLength(value);
        }

        //add padding for the block cipher before encryption
        public byte[] addPadding(byte[] content, int size)
        {
            if (size % 8 == 0)
            {
                return content;
            }

            int extra = 8 - (size % 8);

            byte[] pContent = new byte[size + extra];

            Buffer.BlockCopy(content, 0, pContent, 0, size);

            byte b = (byte)' ';

            for (int i = size; i < pContent.Length; i++)
            {
                pContent[i] = b;
            }

            content = pContent;

            return content;
        }

        //remove the extra padding after decryption
        public byte[] removePadding(byte[] content, int size)
        {
            byte b = (byte)' ';
            if (content[size - 1] != b)
            {
                return content;
            }

            for (int i = size - 1; i >= size - 8; i--)
            {
                if (content[i] == b)
                {
                    content[i] = Convert.ToByte(null);
                    size--;
                }
                else
                {
                    break;
                }
            }

            byte[] pContent = new byte[size];

            Buffer.BlockCopy(content, 0, pContent, 0, size);

            content = pContent;

            return content;
        }

    }
}
