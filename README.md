# NetLens

## Setup
1. Clone the repo
2. Create a virtual environment:
   python -m venv venv
   venv\Scripts\activate
3. Install dependencies:
   pip install -r requirements.txt

## Branch workflow
- main = always working
- Create your own branch off main for your part
- Push, open a PR into main, get it reviewed before merging

## Who owns what
- capture/     -> Person A
- decoder/     -> Person B
- storage/     -> Person C
- shared/packet_record.py -> shared contract, do not edit without agreement
