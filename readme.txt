First, you must cd to where the java files are:

% cd path/to/java/files

The java program must be compiled and then run as a shell command:

% javac PacketAnalyzer.java
% java PacketAnalyzer.java path/to/datafile

The packets are in the folder of the project, so an example of a command would be:

% java PacketAnalyzer.java ../../../../pkt/new_tcp_packet1.bin

The path to the data file will vary based on where the packet files are located on the system
the program is running on. You will get an error if the file path is not correct. If you get
an error, please check where the packets are located and try again. The output should be displayed
in the terminal.


