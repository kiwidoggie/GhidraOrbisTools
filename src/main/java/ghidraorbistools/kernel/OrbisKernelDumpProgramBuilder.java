package ghidraorbistools.kernel;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

import ghidra.app.plugin.assembler.sleigh.util.GhidraDBTransaction;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined6DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidraorbistools.OrbisProgramBuilder;

public class OrbisKernelDumpProgramBuilder extends OrbisProgramBuilder
{
	protected FlatProgramAPI m_Api;
	
	protected OrbisKernelDumpProgramBuilder(ByteProvider p_Provider, Program p_Program,
			MemoryConflictHandler p_Handler) 
	{
		super(p_Provider, p_Program, p_Handler);
		
		m_Api = new FlatProgramAPI(p_Program);
	}

	@Override
	protected void loadDefaultSegments(TaskMonitor p_Monitor)
			throws IOException, AddressOverflowException, AddressOutOfBoundsException 
	{
		long s_ImageBaseAddress = m_Header.getImageBase();
		AddressSpace s_AddressSpace = m_Program.getAddressFactory().getDefaultAddressSpace();
		
		InputStream s_KernelInputStream = m_ByteProvider.getInputStream(0);
		
		m_MemoryBlockUtil.createInitializedBlock(".kernel", s_AddressSpace.getAddress(s_ImageBaseAddress), s_KernelInputStream, m_ByteProvider.length(), "", null, true, true, true, p_Monitor);
	
	}
	
	public static void LoadKernelDump(ByteProvider p_Provider, Program p_Program, MemoryConflictHandler p_Handler, TaskMonitor p_Monitor)
	{
		OrbisKernelDumpProgramBuilder s_Builder = new OrbisKernelDumpProgramBuilder(p_Provider, p_Program, p_Handler);
		// Start a transaction on the program database
		GhidraDBTransaction s_Transaction = new GhidraDBTransaction(p_Program, "Orbis (PlayStation 4) Loader");
		
		s_Builder.load(p_Monitor);
		
		s_Builder.FindSyscalls();
		
		s_Transaction.commit();
		s_Transaction.close();
	}
	
	public void FindSyscalls()
	{
		// We need to find the 'ORBIS kernel SELF' magic
		Address s_MagicOffset = m_Api.findBytes(m_Program.getImageBase(), "\\x4F\\x52\\x42\\x49\\x53\\x20\\x6B\\x65\\x72\\x6E\\x65\\x6C\\x20\\x53\\x45\\x4C\\x46");
		if (s_MagicOffset == null)
		{
			System.out.println("err: could not find ORBIS kernel SELF magic");
			return;
		}
		
		// TODO: Attempt to use getReferenceFromTo/From
		Reference[] s_Reference = m_Api.getReferencesTo(s_MagicOffset);
		
		// Hack job, hack job, yeah that's mee!
		String s_SearchPattern = String.format("\\x%02X\\x%02X\\x%02X\\x%02X\\xFF\\xFF\\xFF\\xFF", 
				(s_MagicOffset.getOffset() & 0xFF), 
				((s_MagicOffset.getOffset() >> 0x8) & 0xFF), 
				((s_MagicOffset.getOffset() >> 0x10) & 0xFF), 
				((s_MagicOffset.getOffset() >> 0x18) & 0xFF));
		
		Address s_RefAddress = m_Api.findBytes(m_Program.getImageBase(), s_SearchPattern);
		if (s_RefAddress == null)
		{
			System.out.println("ripperoini in peperoini");
			return;
		}
		
		Address s_SysVecAddress = s_RefAddress.subtract(0x60);
		try {
			m_Api.createLabel(s_SysVecAddress, "self_orbis_sysvec", true);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Create the structure that we want to apply
		StructureDataType s_SysentType = new StructureDataType(CategoryPath.ROOT, "sysent_t", 0);
		s_SysentType.add(new UnsignedIntegerDataType(), "sy_narg", "number of arguments");
		s_SysentType.add(new Undefined4DataType(), "", "");
		s_SysentType.add(new UnsignedLongLongDataType(), "sy_call", "implementing function");
		s_SysentType.add(new UnsignedShortDataType(), "sy_auevent", "audit event associated with syscall");
		s_SysentType.add(new Undefined6DataType(), "", "");
		s_SysentType.add(new UnsignedLongLongDataType(), "sy_systrace_args_func", "optional argument conversion function");
		s_SysentType.add(new UnsignedIntegerDataType(), "sy_entry", "DTrace entry ID for systrace");
		s_SysentType.add(new UnsignedIntegerDataType(), "sy_return", "DTrace return ID for systrace");
		s_SysentType.add(new UnsignedIntegerDataType(), "sy_flags", "General flags for system calls");
		s_SysentType.add(new UnsignedIntegerDataType(), "sy_thrcnt", "");
		
		
		ArrayList<String> s_SyscallNames = new ArrayList<String>();
		// Read out the number of syscalls
		try {

					
			// Read out the syscall count number
			long s_SyscallCount = m_Api.getLong(s_SysVecAddress);
			
			// Read out the sysent offset
			long s_SysentOffset = m_Api.getLong(s_SysVecAddress.add(0x8));
			
			// Get the address space, and the sysent address
			FunctionManager s_FunctionManager = m_Program.getFunctionManager();
			AddressSpace s_AddressSpace = m_Program.getAddressFactory().getDefaultAddressSpace();
			Address s_SysentAddress = s_AddressSpace.getAddress(s_SysentOffset);
			
			// Label sysent
			m_Api.createLabel(s_SysentAddress, "sysent", true);
			
			System.out.println(String.format("labeling %d syscalls.", s_SyscallCount));
			
			// Iterate through each of the syscalls and label them
			long s_SyscallNamesOffset = m_Api.getLong(s_SysVecAddress.add(0xD0));
			
			// Parse all of the syscall string names
			for (long i = 0; i < s_SyscallCount; ++i)
			{
				// Get the position of the syscall name
				long l_Pos = s_SyscallNamesOffset + (0x8 * i);
				
				// Get the position as an address
				Address l_Address = s_AddressSpace.getAddress(l_Pos);
				
				// Read from the data the offset of the specific name
				long l_NameOffset = m_Api.getLong(l_Address.add(0));
				Address l_NameAddress = s_AddressSpace.getAddress(l_NameOffset);
				
				byte l_Byte = 0;
				Address l_ReadAddress = l_NameAddress;
				String l_Name = "";
				while ((l_Byte = m_Api.getByte(l_ReadAddress)) != 0)
				{
					l_Name += (char)l_Byte;
					l_ReadAddress = l_ReadAddress.add(1);
				}
				
				// Read out the syscall name
				String l_SyscallName = l_Name;
				
				// Do some filtering
				if (l_SyscallName.contains("#") || l_SyscallName.contains("obs_{"))
					l_SyscallName = String.format("nosys_%d", i);
				
				// Add it to the list
				s_SyscallNames.add(l_SyscallName);				
			}
			
			// Iterate through all of the syscalls and label/create code on them
			for (long i = 0; i < s_SyscallCount; ++i)
			{
				String l_SyscallName = s_SyscallNames.get((int) i);
				
				// Get the address of the sysent struct
				long l_SysentObjectOffset = s_SysentOffset + (i * 0x30);
				
				Address l_SyscallSysentOffset = s_AddressSpace.getAddress(l_SysentObjectOffset);
				
				for (int j = 0; j < 0x30; ++j)
					m_Api.removeDataAt(l_SyscallSysentOffset.add(j));
				
				m_Api.createData(l_SyscallSysentOffset, s_SysentType);
				
				m_Api.setPreComment(l_SyscallSysentOffset, String.format("[%d] %s", i, l_SyscallName));
				
				long l_SyscallFunction = m_Api.getLong(l_SyscallSysentOffset.add(0x8));
				Address l_SyscallFunctionAddress = s_AddressSpace.getAddress(l_SyscallFunction);
				
				AddressSet l_AddressSet = new AddressSet(l_SyscallFunctionAddress);
				
				m_Api.createFunction(l_SyscallFunctionAddress, l_SyscallName);
				//s_FunctionManager.createFunction(l_SyscallName, l_SyscallFunctionAddress, l_AddressSet, SourceType.USER_DEFINED);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
