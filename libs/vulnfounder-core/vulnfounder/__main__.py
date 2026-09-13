"""Allow running ``python -m vulnfounder``."""
from vulnfounder.cli import main
import sys

sys.exit(main())
