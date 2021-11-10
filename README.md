# msusel-pique-bin
## Introduction
This project is an operationalized PIQUE model for the assessment of security quality in binary files. 

PIQUE is not yet added to the Maven central repository, so this project will need to be [built](#building) and installed (via Maven) before it can be used as a library. 
___
## Tools
These will be automatically installed through python/docker when PIQUE-Bin is run.

- [YARA](http://virustotal.github.io/yara/) and the [Yara-Rules repository](https://github.com/Yara-Rules/rules)
- [CVE-Bin-Tool](https://github.com/intel/cve-bin-tool)
- [CWE_Checker](https://github.com/fkie-cad/cwe_checker)
___

## Build Environment
- Java 8
- Maven
- Python 3.6+
- Docker
- [PIQUE](https://github.com/MSUSEL/msusel-pique)
___
## Building and Running
1. Ensure the [Build Environment](#build-environment) requirements are met, including having already built [PIQUE](https://github.com/MSUSEL/msusel-pique).
2. Clone repository into `<project_root>` folder.
3. Derive the model as defined in the [Model Derivation](#model-derivation) section below
4. Assess a binary as defined in the [Binary Analysis](#binary-analysis) section below

### Model Derivation
First the model must be configured in the `src/main/resources/pique-bin.properties` file. Then, the model must be derived using a benchmark repository. This is done by running the `src/main/java/piquebinaries/runnable/QualityModelDeriver.java` file.

### Binary Analysis
Finally, the `src/main/java/piquebinaries/runnable/SingleProjectEvaluator.java` file may be run to analyze a binary. This will produce output in the `/out` folder. This can also be done through running the .jar file produced when the project is packaged. 

## Packaging into a .jar file
PIQUE-Bin may be package into a jar file to perform assessments with. Currently we do not support model derivation using the binary. That means that model derivation must be completed before packaging PIQUE-Bin into a jar. Once this has been completed, run the `mvn package` command to create the jar file. The pique-properties.properties file must be brought into the same directory as the jar, as well as the derived quality model JSON that was produced in the derivation stage. The pique-properties.properties file must be adjusted to point to this derived model.

## Notes
Currently, we have not done testing to ensure that this will run on non-Windows environments however, we have developed this with cross-platform compatability. Additionally, one test is ignored becuase it is known to be failing: the cve-bin-tool ToolShouldHaveNoFindingsOnSimpleCleanBinary test. This test checks that an extremely simple binary will produce no findings; however, we find that the binary does have findings stemming from glibc.
