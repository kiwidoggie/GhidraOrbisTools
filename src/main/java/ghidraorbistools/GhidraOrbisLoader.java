/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraorbistools;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidraorbistools.kernel.OrbisKernelDumpProgramBuilder;

/**
 * This is the ELF loader for PlayStation 4 executables
 * 
 * Currently Supported: Full kernel memory dumps
 * 
 * Future: User land elfs
 */
public class GhidraOrbisLoader extends BinaryLoader 
{
	enum ExecutableType
	{
		// Invalid option
		Invalid,
		
		// Dumped kernel ELF's
		KernelDump,
		
		// Userland ELF's
		UserElf
	}
	
	private ExecutableType m_ExecutableType;
	
	public GhidraOrbisLoader()
	{
		// We start off with an invalid elf type as we have not parsed anything
		m_ExecutableType = ExecutableType.Invalid;
	}
	
	@Override
	public String getName() 
	{
		return "Orbis (PlayStation 4) Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider p_Provider) throws IOException {
		List<LoadSpec> s_LoadSpecs = new ArrayList<>();
		
		ElfHeader s_ElfHeader = null;
		// Read out the header information
		try {
			ElfHeaderFactory<ElfHeader> s_ElfFactory = new ElfHeaderFactory<ElfHeader>();
			s_ElfHeader = ElfHeader.createElfHeader(s_ElfFactory, p_Provider);
			s_ElfHeader.parse();
		} catch (ElfException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Verify that we are 64 bit
		if (!s_ElfHeader.is64Bit())
			return s_LoadSpecs;
		
		// Get the header base address
		long s_ImageBase = s_ElfHeader.getImageBase();
		
		// Check that we are in user space, and exit if we are
		if ( (s_ImageBase & 0x8000000000000000L) == 0)
			m_ExecutableType = ExecutableType.UserElf;
		else
			m_ExecutableType = ExecutableType.KernelDump;
		
		// Create the new PS4 specification, requires clang
		s_LoadSpecs.add(new LoadSpec(this, s_ImageBase, new LanguageCompilerSpecPair("x86:LE:64:default", "gcc"), true));
		
		return s_LoadSpecs;
	}
	
	@Override
	public List<Program> loadProgram(ByteProvider p_Provider, String p_ProgramName, DomainFolder p_ProgramFolder, LoadSpec p_LoadSpec, List<Option> p_Options, MessageLog p_Log, Object p_Consumer, TaskMonitor p_Monitor) throws IOException, CancelledException 
	{
		LanguageCompilerSpecPair pair = p_LoadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

        Address baseAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Program s_Program = createProgram(p_Provider, p_ProgramName, baseAddr, getName(), importerLanguage, importerCompilerSpec, p_Consumer);
        boolean s_Success = false;
        
        try 
        {
            s_Success = this.loadInto(p_Provider, p_LoadSpec, p_Options, p_Log, s_Program, p_Monitor, MemoryConflictHandler.ALWAYS_OVERWRITE);
        }
        finally 
        {
            if (!s_Success) 
            {
                s_Program.release(p_Consumer);
                s_Program = null;
            }
        }
        
        List<Program> results = new ArrayList<Program>();
        
        if (s_Program != null) 
        	results.add(s_Program);
        
		return results;
	}
	
	@Override
    protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor, MemoryConflictHandler memoryConflictHandler) 
            throws IOException
    {
        // Handle the different ELF types
        switch (m_ExecutableType)
        {
        case UserElf:
        	messageLog.appendMsg("userland elf: currently not supported");
        	return false;
        case KernelDump:
        	OrbisKernelDumpProgramBuilder.LoadKernelDump(provider, program, memoryConflictHandler, monitor);
        	break;
    	default:
    		messageLog.appendMsg("invalid executable type, loading canceled");
    		return false;
        }
        
        return true;
    }
	
	@Override
	public LoaderTier getTier()
	{
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}
}
