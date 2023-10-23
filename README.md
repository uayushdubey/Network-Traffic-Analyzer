Network Traffic Analyzer
Introduction
The Network Traffic Analyzer is a Python program that allows users to analyze and visualize network traffic data. It provides a graphical user interface (GUI) for users to input source and destination IP addresses, along with a password. The program uses the NetworkX library to create a directed graph representation of the traffic data and provides various functionalities such as adding traffic data, displaying a traffic graph, calculating distances between IP addresses, and removing IP addresses from the graph.

Key Concepts
NetworkX: NetworkX is a Python library used for the creation, manipulation, and study of the structure, dynamics, and functions of complex networks. In this program, NetworkX is used to represent the network traffic data as a directed graph.

PyQt5: PyQt5 is a set of Python bindings for Qt libraries. It provides a comprehensive set of GUI components for creating desktop applications. In this program, PyQt5 is used to create the graphical user interface (GUI) for the Network Traffic Analyzer.

bcrypt: bcrypt is a password hashing function designed to be slow and computationally expensive, making it difficult for attackers to crack hashed passwords. In this program, bcrypt is used to hash the passwords before storing them in the traffic data file.

Code Structure
The code is structured as follows:

Importing the necessary libraries and modules:

sys: Provides access to some variables used or maintained by the interpreter and to functions that interact with the interpreter.
networkx: A Python library for the creation, manipulation, and study of the structure, dynamics, and functions of complex networks.
matplotlib.pyplot: A plotting library for the Python programming language.
bcrypt: A password hashing function.
PyQt5.QtWidgets: Provides a set of UI components for creating desktop applications.
PyQt5.QtGui: Provides a set of graphical user interface components for creating desktop applications.
Creating the main application window:

QApplication: Initializes the PyQt5 application.
QMainWindow: Represents the main application window.
QPalette: Manages the color palette of the application.
QPixmap: Represents an image in the application.
QWidget: Represents a widget in the application.
QVBoxLayout: Arranges the child widgets vertically.
QHBoxLayout: Arranges the child widgets horizontally.
QPushButton: Represents a push button in the application.
QLabel: Represents a text label in the application.
QLineEdit: Represents a single-line input field in the application.
QGridLayout: Arranges the child widgets in a grid layout.
QMessageBox: Displays a message box in the application.
Defining the layout and adding UI components:

layout: Represents the main layout of the application.
form_layout: Represents the layout for the input fields.
button_layout: Represents the layout for the buttons.
add_button: Represents the button for adding traffic data.
graph_button: Represents the button for displaying the traffic graph.
distance_button: Represents the button for displaying distances between IP addresses.
remove_ip_label: Represents the label for the remove IP address input field.
remove_ip_input: Represents the input field for removing an IP address.
remove_button: Represents the button for removing an IP address.
Creating a directed graph using NetworkX:

G: Represents the directed graph object created using NetworkX.
Defining functions for button click events:

add_traffic(): Adds traffic data to the graph and stores it in a text file.
display_traffic_graph(): Displays the traffic graph using NetworkX and matplotlib.
display_distances(): Calculates and displays the distances between IP addresses.
remove_ip(): Removes an IP address from the graph.
Connecting the button click events to their respective functions.

Displaying the main application window and running the PyQt5 application.

here are some code examples to illustrate the usage of the Network Traffic Analyzer:

---------------------
Adding Traffic Data:
---------------------

def add_traffic():
    source_ip = source_input.text()
    dest_ip = dest_input.text()
    password = password_input.text()

    if source_ip and dest_ip and password:
        # Encrypt the password using bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        G.add_edge(source_ip, dest_ip)

        # Store traffic data in a text file
        with open('traffic_data.txt', 'a') as file:
            file.write(f'Source IP: {source_ip}, Destination IP: {dest_ip}, Password Hash: {password_hash.decode("utf-8")}\n')

        source_input.clear()
        dest_input.clear()
        password_input.clear()

add_button.clicked.connect(add_traffic)

-------------------------
Displaying Traffic Graph:
--------------------------
def display_traffic_graph():
    if len(G) > 0:
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_size=500, node_color='lightblue')
        plt.title("Network Traffic Analysis")
        plt.show()
    else:
        print("No traffic data to display.")

graph_button.clicked.connect(display_traffic_graph)

-----------------------
Displaying Distances:
----------------------

def display_distances():
    distances = {}
    for node in G.nodes:
        distances[node] = nx.shortest_path_length(G, source=node)

    distance_message = "Distances of IP addresses:\n"
    for node, distance in distances.items():
        distance_message += f"{node}: {distance}\n"

    msg_box = QMessageBox()
    msg_box.setWindowTitle('Node Distances')
    msg_box.setText(distance_message)
    msg_box.exec_()

distance_button.clicked.connect(display_distances)

----------------------
Removing IP Address:
---------------------


def remove_ip():
    ip_to_remove = remove_ip_input.text()
    if ip_to_remove:
        try:
            G.remove_node(ip_to_remove)
            remove_ip_input.clear()
        except nx.NetworkXError:
            print(f"IP address {ip_to_remove} not found in the graph.")

remove_button.clicked.connect(remove_ip)
