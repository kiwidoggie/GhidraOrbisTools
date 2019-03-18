package ghidraorbistools;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public abstract class OrbisProgramBuilder 
{
	protected ElfHeader m_Header;
	protected ByteProvider m_ByteProvider;
	protected BinaryReader m_BinaryReader;
	protected Program m_Program;
	protected MemoryBlockUtil m_MemoryBlockUtil;
	
	protected ArrayList<ElfProgramHeader> m_ProgramHeaders;
	protected ArrayList<ElfSectionHeader> m_SectionHeaders;
	
	protected OrbisProgramBuilder(ByteProvider p_Provider, Program p_Program, MemoryConflictHandler p_Handler)
    {
		// Read out the header information
		try 
		{
			ElfHeaderFactory<ElfHeader> s_ElfFactory = new ElfHeaderFactory<ElfHeader>();
			m_Header = ElfHeader.createElfHeader(s_ElfFactory, p_Provider);
			m_Header.parse();
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Set the provider, program, and create a new memory utility
        m_ByteProvider = p_Provider;
        m_Program = p_Program;
        m_MemoryBlockUtil = new MemoryBlockUtil(p_Program, p_Handler);
    }
    
	// Each of the loaders will have to implement this
	protected abstract void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException;
	
    protected void load(TaskMonitor monitor)
    {
        // Get the image base address from the header, this is the only thing we will use from the header
    	long s_ImageBaseAddress = m_Header.getImageBase();
        AddressSpace s_AddressSpace = m_Program.getAddressFactory().getDefaultAddressSpace();
        
        try 
        {
            // Set the base address
            m_Program.setImageBase(s_AddressSpace.getAddress(s_ImageBaseAddress), true);
            m_BinaryReader = new BinaryReader(m_ByteProvider, true);
            
            loadDefaultSegments(monitor);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException e) 
        {
            e.printStackTrace();
        }
    }
}
