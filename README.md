# Trazer
Allows the user to define templates to mactch Wireshark traces. 
Basically, a template is a test case (TC). It is matched against a Wireshark trace to check whether specific conditions are met. If they are met, then the TC is passed. Otherwise the TC fails and human analysis is required.

# Scope
Our target is to develop a tool that can be used to automatise acceptance testing of IMS, 4G and 5G system. However, we want to develop this tool in a generic way, so it can be used in any kind of testing where Wireshark traces need to be rutinely analysed to conclude whether a test case is passed or not.

