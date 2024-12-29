
// Description
// Runs the "PDB Universal" analyzer for all programs in the project.
//@author sweet.giorni
//@category Windows
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

public class PDBUniversalAnalyzeAll extends GhidraScript {

	MessageLog log = new MessageLog();

	@Override
	public void run() throws Exception {

		PluginTool tool = state.getTool();
		Project project = tool.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder rootFolder = projectData.getRootFolder();
		recurseProjectFolder(rootFolder);
	}

	private void recurseProjectFolder(DomainFolder domainFolder) throws Exception {
		DomainFile[] files = domainFolder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCancelled();
			try {
				processDomainFile(domainFile);
			}
			catch (Exception ex) {
				printerr(ex.getMessage());
			}
		}
		DomainFolder[] folders = domainFolder.getFolders();
		for (DomainFolder folder : folders) {
			monitor.checkCancelled();
			recurseProjectFolder(folder);
		}
	}

	private void processDomainFile(DomainFile domainFile) throws Exception {
		Map<String, String> metadata = domainFile.getMetadata();
		if (metadata == null) {
			return;
		}
		String formatString = metadata.get("Executable Format");
		if (formatString == null) {
			return;
		}
		if (!formatString.equals("Portable Executable (PE)")) {
			return;
		}
		DomainObject domainObject = domainFile.getDomainObject(this, false, true, monitor);
		try {
			Program program = (Program) domainObject;
			monitor.setMessage("Processing program...");
			processProgram(program);
			monitor.setMessage("Saving program...");
			saveProgram(program);
		}
		finally {
			domainObject.release(this);
		}
	}

	private void processProgram(Program program) throws CancelledException {
		println("Loading symbols for program: " + program.getName());
		int id = program.startTransaction("Loading symbols");
		boolean success = false;

		try {
			AutoAnalysisManager m = AutoAnalysisManager.getAnalysisManager(program);
			PdbUniversalAnalyzer analyzer = (PdbUniversalAnalyzer) m.getAnalyzer("PDB Universal");
			PdbUniversalAnalyzer.setAllowUntrustedOption(program, true);

			success = analyzer.added(program, program.getMemory(), monitor, this.log);
		}
		finally {
			program.endTransaction(id, success);
		}
	}

}