
# stdlib
from pprint import pprint

# python-cybox
from cybox.common import ToolInformationList, ToolInformation

# python-stix
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource



def main():
    # Create a new STIXPackage
    stix_package = STIXPackage()

    # Create a new STIXHeader
    stix_header = STIXHeader()

    # Add Information Source. This is where we will add the tool information.
    stix_header.information_source = InformationSource()

    # Create a ToolInformation object. Use the initialization parameters
    # to set the tool and vendor names.
    #
    # Note: This is an instance of cybox.common.ToolInformation and NOT
    # stix.common.ToolInformation.
    tool = ToolInformation(
        tool_name="ELFPack",
        tool_vendor="X-Force, IBM Corporation"
    )

    # Set the Information Source "tools" section to a
    # cybox.common.ToolInformationList which contains our tool that we
    # created above.
    stix_header.information_source.tools = ToolInformationList(tool)

    # Set the header description
    stix_header.description = "ELFPack STIX definitions"

    # Set the STIXPackage header
    stix_package.stix_header = stix_header

    # Print the XML!
    print(stix_package.to_xml(pretty=True))

    # Print the dictionary!
    pprint(stix_package.to_dict())


if __name__ == '__main__':
    main()
