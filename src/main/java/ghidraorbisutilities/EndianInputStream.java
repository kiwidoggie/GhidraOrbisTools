/**
 * Fuck java
 */
package ghidraorbisutilities;

import java.io.DataInput;
import java.io.*;

/**
 * @author Peter Franza (original implementation) - https://www.peterfranza.com/2008/09/26/little-endian-input-stream/
 * @author kiwidog (endianness modification) - http://github.com/OpenOrbis
 *
 */
public class EndianInputStream extends InputStream implements DataInput {
	public enum Endianness {
		LittleEndian,
		BigEndian,
	}
	
	private DataInputStream m_inputDataStream;
	private InputStream m_inputStream;
	private byte m_buffer[];
	
	private Endianness m_endianness;
	
	private static int BufferSize = 8;
	
	public EndianInputStream(InputStream inputStream, Endianness endianness) {
		m_inputStream = inputStream;
		m_inputDataStream = new DataInputStream(m_inputStream);
		m_buffer = new byte[BufferSize];
		m_endianness = endianness;
	}
	
	public int available() throws IOException {
		return m_inputDataStream.available();
	}
 
 
	public final short readShort() throws IOException
	{
		// Handle little endian
		if (m_endianness == Endianness.LittleEndian)
		{
			m_inputDataStream.readFully(m_buffer, 0, 2);
			return (short)(
					(m_buffer[1]&0xff) << 8 |
					(m_buffer[0]&0xff));
		}
		
		// Handle big endian
		return m_inputDataStream.readShort();
	}
 
	/**
	 * Note, returns int even though it reads a short.
	 */
	 public final int readUnsignedShort() throws IOException
	 {
		 // Handle little endian
		 if (m_endianness == Endianness.LittleEndian)
		 {
			 m_inputDataStream.readFully(m_buffer, 0, 2);
			 return (
					 (m_buffer[1]&0xff) << 8 |
					 (m_buffer[0]&0xff));
		 }
		 
		 // Handle big endian
		 return m_inputDataStream.readShort();
	 }
 
	 /**
	  * like DataInputStream.readChar except little endian.
	  */
	 public final char readChar() throws IOException
	 {
		 if (m_endianness == Endianness.LittleEndian)
		 {
			 m_inputDataStream.readFully(m_buffer, 0, 2);
			 return (char) (
					 (m_buffer[1]&0xff) << 8 |
					 (m_buffer[0]&0xff));
		 }
		 
		 return m_inputDataStream.readChar();
	 }
 
	 /**
	  * like DataInputStream.readInt except little endian.
	  */
	 public final int readInt() throws IOException
	 {
		 if (m_endianness == Endianness.LittleEndian)
		 {
			 m_inputDataStream.readFully(m_buffer, 0, 4);
			 return
			 (m_buffer[3])      << 24 |
			 (m_buffer[2]&0xff) << 16 |
			 (m_buffer[1]&0xff) <<  8 |
			 (m_buffer[0]&0xff);
		 }
		 
		 return m_inputStream.read();
	 }
 
	 /**
	  * like DataInputStream.readLong except little endian.
	  */
	 @SuppressWarnings("cast")
	public final long readLong() throws IOException
	 {
		 if (m_endianness == Endianness.LittleEndian)
		 {
			 m_inputDataStream.readFully(m_buffer, 0, 8);
			 return
			 (long)(m_buffer[7])      << 56 | 
			 (long)(m_buffer[6]&0xff) << 48 |
			 (long)(m_buffer[5]&0xff) << 40 |
			 (long)(m_buffer[4]&0xff) << 32 |
			 (long)(m_buffer[3]&0xff) << 24 |
			 (long)(m_buffer[2]&0xff) << 16 |
			 (long)(m_buffer[1]&0xff) <<  8 |
			 (long)(m_buffer[0]&0xff);
		 }
		 return m_inputDataStream.readLong();
	 }
 
	 public final float readFloat() throws IOException {
		 return Float.intBitsToFloat(readInt());
	 }
 
	 public final double readDouble() throws IOException {
		 return Double.longBitsToDouble(readLong());
	 }
 
	 public final int read(byte b[], int off, int len) throws IOException {
		 return m_inputStream.read(b, off, len);
	 }
 
	 public final void readFully(byte b[]) throws IOException {
		 m_inputDataStream.readFully(b, 0, b.length);
	 }
 
	 public final void readFully(byte b[], int off, int len) throws IOException {
		 m_inputDataStream.readFully(b, off, len);
	 }
 
	 public final int skipBytes(int n) throws IOException {
		 return m_inputDataStream.skipBytes(n);
	 }
 
	 public final boolean readBoolean() throws IOException {
		 return m_inputDataStream.readBoolean();
	 }
 
	 public final byte readByte() throws IOException {
		 return m_inputDataStream.readByte();
	 }
 
	 public int read() throws IOException {
		 return m_inputStream.read();
	 }
 
	 public final int readUnsignedByte() throws IOException {
		 return m_inputDataStream.readUnsignedByte();
	 }
 
	 @Deprecated
	 public final String readLine() throws IOException {
		 return m_inputDataStream.readLine();
	 }
 
	 public final String readUTF() throws IOException {
		 return m_inputDataStream.readUTF();
	 }
 
	 public final void close() throws IOException {
		 m_inputDataStream.close();
	 }

}
