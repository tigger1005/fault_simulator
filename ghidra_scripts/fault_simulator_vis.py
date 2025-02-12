# Visualises an instruction trace of fault_simulator
# @author Dominik Zuerner <dominik@zuerner.at>
# @keybinding 
# @menupath 
# @toolbar

# More information:
# https://github.com/tigger1005/fault_simulator
# License: MIT

import re
import javax.swing as swing
from java.awt import Color, Dimension
from javax.swing import JOptionPane, JScrollPane, JTextArea
from java.awt.event import WindowAdapter, WindowEvent
from ghidra.program.model.listing import CodeUnit

# @runtime PyGhidra

# Initialize variables
addresses_and_comments = []
fault_addresses = []

# Regex patterns
address_pattern = re.compile(r'^(0x[0-9A-Fa-f]+):.*<([^>]*)>')
fault_pattern = re.compile(r'^->')

# Function to get multiline user input using a dialog box
def get_multiline_input(prompt, title, rows=10, columns=40):

    text_area = JTextArea(rows, columns)
    scroll_pane = JScrollPane(text_area)
    scroll_pane.setPreferredSize(Dimension(500, 300))
    
    prompt_label = swing.JLabel(prompt)
    
    panel = swing.JPanel()
    panel.setLayout(swing.BoxLayout(panel, swing.BoxLayout.Y_AXIS))
    
    panel.add(prompt_label)
    panel.add(scroll_pane)
    
    # Show the input dialog with the panel
    result = JOptionPane.showConfirmDialog(None, panel, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
    
    # Return the text if the user pressed OK
    if result == JOptionPane.OK_OPTION:
        return text_area.getText()
    else:
        return None

# Function to parse the log file content
def parse_log_content(log_content):
    lines = log_content.splitlines()
    for i, line in enumerate(lines):
        # Check for address line
        match = address_pattern.match(line)
        if match:
            address = match.group(1)
            comment = match.group(2).strip()
            addresses_and_comments.append((address, comment))
        
        # Check for fault line
        if fault_pattern.match(line):
            # The fault address is in the next line
            next_line = lines[i + 1] if i + 1 < len(lines) else None
            if next_line:
                fault_match = address_pattern.match(next_line)
                if fault_match:
                    fault_address = fault_match.group(1)
                    fault_addresses.append(fault_address)

# Function to highlight the isntruction trace
def highlight_trace(addresses, highlight=True):
    # Get the current program
    currentProgram = getCurrentProgram()
    if currentProgram is None:
        print("No current program found.")
        return
    
    # Get the listing of the program
    listing = currentProgram.getListing()
    
    # Define the red color for highlighting
    green_color = Color(0, 80, 0)
    
    for address_str in addresses:
        # Convert the string address to an Address object
        address = toAddr(address_str)
        if address is None:
            print("Invalid address: {}".format(address_str))
            continue
        
        # Get the code unit at the address
        code_unit = listing.getCodeUnitAt(address)
        if code_unit is None:
            print("No code unit found at address: {}".format(address_str))
            continue
        
        # Highlight or remove highlight for the code unit
        if highlight:
            setBackgroundColor(address, green_color)
            #print("Address {}: Highlighted".format(address_str))
        else:
            clearBackgroundColor(address)  # Remove color
            #print("Address {}: Highlight removed".format(address_str))

# Function to highlight the fault addresses
def highlight_faults(addresses, highlight=True):
    # Get the current program
    currentProgram = getCurrentProgram()
    if currentProgram is None:
        print("No current program found.")
        return
    
    # Get the listing of the program
    listing = currentProgram.getListing()
    
    # Define the red color for highlighting
    red_color = Color(255, 50, 50) 
    
    for address_str in addresses:
        # Convert the string address to an Address object
        address = toAddr(address_str)
        if address is None:
            print("Invalid address: {}".format(address_str))
            continue
        
        # Get the code unit at the address
        code_unit = listing.getCodeUnitAt(address)
        if code_unit is None:
            print("No code unit found at address: {}".format(address_str))
            continue
        
        # Highlight or remove highlight for the code unit
        if highlight:
            setBackgroundColor(address, red_color)
            #print("Address {}: Highlighted".format(address_str))
        else:
            clearBackgroundColor(address)  # Remove color
            #print("Address {}: Highlight removed".format(address_str))

# Function to set EOL comments in Ghidra
def set_eol_comments(self):
    currentProgram = getCurrentProgram()
    if currentProgram is None:
        print("No current program found.")
        return

    listing = currentProgram.getListing()

    for address_str, comment in self.addresses_and_comments:
        address = toAddr(address_str)
        if address is None:
            print("Invalid address: {}".format(address_str))
            continue

        code_unit = listing.getCodeUnitAt(address)
        if code_unit is None:
            print("No code unit found at address: {}".format(address_str))
            continue

        code_unit.setComment(CodeUnit.EOL_COMMENT, comment)
        print("Set EOL comment at address {}: {}".format(address_str, comment))

# Function to display the table where we ca scroll through the trace
def display_table(addresses_and_comments):
    # Define the column names and data for the table
    column_names = ["Address", "Comment"]
    data = []

    for address, comment in addresses_and_comments:
        data.append([address, comment])

    # Create the table with the data
    table = swing.JTable(data, column_names)

    # Create a selection listener to handle row selection
    def on_table_selection(event):
        if event.getValueIsAdjusting():
            return

        selected_row = table.getSelectedRow()
        if selected_row != -1:
            address_str = table.getValueAt(selected_row, 0)
            address = toAddr(address_str)
            setCurrentLocation(address)

    # Add the listener to the table's selection model
    selection_model = table.getSelectionModel()
    selection_model.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)
    selection_model.addListSelectionListener(on_table_selection)

    # Create a scroll pane and add the table to it
    scroll_pane = swing.JScrollPane(table)

    # Create a frame and add the scroll pane to it
    frame = swing.JFrame("fault_simulator Trace")
    frame.setDefaultCloseOperation(swing.JFrame.DISPOSE_ON_CLOSE)
    frame.setSize(500, 300)
    frame.add(scroll_pane)

    # Define the actions to perform when the window is closing
    def on_window_closing():
        currentProgram = getCurrentProgram()
        if currentProgram is None:
            print("No current program found.")
            return
        # Transaction needed to remove highlights. Haven't fully understood this yet.
        transaction = currentProgram.startTransaction("Remove Highlights")
        try:
            highlight_trace([addr for addr, comment in addresses_and_comments], highlight=False)
            highlight_faults(fault_addresses, highlight=False)
            print("Highlights removed")
        finally:
            currentProgram.endTransaction(transaction, True)

    # Add a window listener to handle the window closing event
    class WindowCloseListener(WindowAdapter):
        def __init__(self, close_action):
            self.close_action = close_action

        def windowClosing(self, event):
            self.close_action()

    # Set the window close listener to the frame
    frame.addWindowListener(WindowCloseListener(on_window_closing))

    # Show the frame
    frame.setVisible(True)

def main():
    prompt = "Please enter the trace output:"
    title = "Trace Input Dialog"
    user_input = get_multiline_input(prompt, title)
    
    if not user_input:
        print("No input received or operation was cancelled.")
        return

    parse_log_content(user_input)

    print("Addresses and Comments:")
    for addr, comment in addresses_and_comments:
        print("{}: {}".format(addr, comment))

    print("\nFault Addresses:")
    for fault_addr in fault_addresses:
        print(fault_addr)

    addresses = [addr for addr, comment in addresses_and_comments]

    highlight_trace(addresses)
    highlight_faults(fault_addresses)

    # Set EOL comments in Ghidra
    # set_eol_comments(addresses_and_comments)

    # Display the table
    display_table(addresses_and_comments)

if __name__ == '__main__':
    main()
