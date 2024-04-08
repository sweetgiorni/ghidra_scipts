
// Description
// For each external function in the current program, check if it can
// be resolved to a function in another program. If so, update the referenced
// function to match the resolved function's signature.
//@author sweet.giorni
//@category Functions
import javax.swing.Icon;

import ghidra.app.nav.LocationMemento;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.FunctionUtility;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class FixExternalFunctionSignatures extends GhidraScript {

	TaskMonitor consoleMonitor = new ConsoleTaskMonitor();
	MessageLog log = new MessageLog();

	@Override
	public void run() throws Exception {
		iterateExternalSymbols(currentProgram, currentSelection, monitor, log);
	}

	public void iterateExternalSymbols(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log)
			throws CancelledException {

		FunctionManager functionManager = program.getFunctionManager();

		GoToHelper goToHelper = new GoToHelper(state.getTool());

		// iterate over all external symbols
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator externalSymbols = symbolTable.getExternalSymbols();
		for (Symbol externalSymbol : externalSymbols) {
			if (externalSymbol.getSymbolType() != SymbolType.FUNCTION) {
				continue;
			}

			Function externalFunction = functionManager.getFunctionAt(externalSymbol.getAddress());
			ExternalLocation externalLocation = externalFunction.getExternalLocation();

			DummyNav dummyNav = new DummyNav();
			goToHelper.goToExternalLocation(dummyNav, externalLocation, false);

			if (dummyNav.getProgram() == null || dummyNav.getLocation() == null) {
				continue;
			}

			Program referencedProgram = dummyNav.getProgram();
			FunctionManager referencedFunctionManager = referencedProgram.getFunctionManager();
			Function referencedFunction = referencedFunctionManager
					.getFunctionContaining(dummyNav.getLocation().getAddress());
			if (referencedFunction == null) {
				Msg.warn(this,
					"Could not locate the referenced function for " + externalSymbol.getName());
				continue;
			}

			try {
				FunctionUtility.updateFunction(externalFunction, referencedFunction);
			}
			catch (Exception e) {
				Msg.error(this, e);
				continue;
			}
		}
	}

	public class DummyNav implements Navigatable {

		static int counter = 0;

		public int instanceID;
		public Program currentProgram;
		public ProgramLocation currentLocation;
		public LocationMemento currentMemento;
		public ProgramSelection currentSelection;
		public ProgramSelection currentHighlight;
		public String textSelection;

		public DummyNav() {
			this.instanceID = DummyNav.counter;
			DummyNav.counter++;
		}

		@Override
		public long getInstanceID() {
			return this.instanceID;
		}

		@Override
		public boolean goTo(Program program, ProgramLocation location) {
			this.currentProgram = program;
			this.currentLocation = location;
			return true;
		}

		@Override
		public ProgramLocation getLocation() {
			return this.currentLocation;
		}

		@Override
		public Program getProgram() {
			return this.currentProgram;
		}

		@Override
		public LocationMemento getMemento() {
			return this.currentMemento;
		}

		@Override
		public void setMemento(LocationMemento memento) {
			this.currentMemento = memento;
		}

		@Override
		public Icon getNavigatableIcon() {
			// TODO Auto-generated method stub
			throw new UnsupportedOperationException("Unimplemented method 'getNavigatableIcon'");
		}

		@Override
		public boolean isConnected() {
			return true;
		}

		@Override
		public boolean supportsMarkers() {
			return true;
		}

		@Override
		public void requestFocus() {
		}

		@Override
		public boolean isVisible() {
			return true;
		}

		@Override
		public void setSelection(ProgramSelection selection) {
			this.currentSelection = selection;
		}

		@Override
		public void setHighlight(ProgramSelection highlight) {
			this.currentHighlight = highlight;
		}

		@Override
		public ProgramSelection getSelection() {
			return this.currentSelection;
		}

		@Override
		public ProgramSelection getHighlight() {
			return this.getHighlight();
		}

		@Override
		public String getTextSelection() {
			return this.textSelection;
		}

		@Override
		public void addNavigatableListener(NavigatableRemovalListener listener) {

		}

		@Override
		public void removeNavigatableListener(NavigatableRemovalListener listener) {

		}

		@Override
		public boolean isDisposed() {
			return false;
		}

		@Override
		public boolean supportsHighlight() {
			return true;
		}

		@Override
		public void setHighlightProvider(ListingHighlightProvider highlightProvider,
				Program program) {
		}

		@Override
		public void removeHighlightProvider(ListingHighlightProvider highlightProvider,
				Program program) {
		}

	}
}