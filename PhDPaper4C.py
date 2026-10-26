# -*- coding: utf-8 -*-
"""
PhDPaper4C v0.13: which structural parameters matter to collapse (screening pass).
=================================================================================

One self-contained file, numpy only. It sweeps every dial of the Knob Register
across its whole range, one dial at a time, against three backgrounds, and
draws the outcome against the dial's value. It studies value ranges and their
effects and makes no reading against any hypothesis.

What is in this file
  1. The frozen cemt_core v0.8 (set digest 97dbae47...), embedded byte for byte
     and hash-checked at load. A mismatch aborts.
  2. The Paper 4B engine (PhDPaper4B v0.23, class Engine4B) and its three estate
     builders, lifted verbatim. They are the reference for Gate 0.
  3. Engine4C, a subclass. With one system, one master and default settings it
     reduces to the 4B engine exactly (same random draws, same outcome); Gate 0
     checks that.
  4. The estate (Paper_4C_Structure_and_Collapse): network zones in which every
     node reaches every other, limited reach between zones; per zone an
     endpoint detection controller and an Active Directory controller, and one
     DNS service for the estate, each taken through its privileged credential;
     software-delivery channels; and entry across the border by each corner of
     the triangle (Interface, Execution Pathway, Authority).
  5. The attack: a payload arrives and leaves a node infected; after its delay
     it triggers and the node's control answers, so the node is captured or the
     payload is repelled; a node held long enough is reconfigured. The game is
     over when 80 per cent of the estate is compromised. Every run starts clean.

Modes (python PhDPaper4C.py --mode MODE)
  selftest   fast checks of the generator, the engine and the analysis.
  gate0      (a) Engine4C equals Engine4B run for run on E8 cells;
             (b) E8 Plane A reproduced. Use --ref PATH to also compare against
             an external PhDPaper4B.py.
  time       time sample runs and project the cost of a sweep.
  smoke      the quick test: the whole sweep cut down (three levels per dial, a
             small grid) to run in well under an hour. Rough numbers; it is for
             checking that everything works and seeing the shape of things.
  sweep      the full value-range sweep. Every task is saved as it completes;
             to resume a stopped run, repeat the command with --run-dir.
  curves     redraw P4C_curves.html from a sweep or smoke directory.
  ablate     the stage-ablation pilot: four stages, mapped to ATT&CK tactics (Initial Access by
             supplier, Privilege Escalation, Credential Access, Lateral
             Movement) switched off singly and together, per attack kind.
  paired     paired sweeps for the masking hypothesis: selected dials swept
             with Credential Access on and off, on seeds and wirings the
             pilots did not use, reported by grid cell as well as on average.
  grid       map every outcome along the two grid axes, per kind and
             background, to show which axes and levels the grid needs.
  confirm    the confirmatory study of masking: a fixed protocol (levels,
             outcome, seeds, wirings and decision rule set in advance) on the
             reserved seeds. Run it once. --quick is a dry run that checks the
             pipeline on other seeds and leaves the reserved ones untouched;
             --run-dir resumes an interrupted run.
  drill      the exposure drill: credential exposure as an absolute count
             scaling up from zero (how many, which service, at what estate
             size), a fixed protocol on the reserved seeds. --quick dry-runs it.
  plan       list what one background of the sweep would run.
  screen     one background only (--point). analyse rebuilds its report.

Useful options: --steps N (at most N levels per dial), --knobs a,b,c,
--backgrounds strong,middle,sealed, --workers N, --run-dir DIR.

Governance scope
  gamma = 0  one governance: one defender observes, cleans and blocks across
             every system, with one pooled budget.
  gamma = 1  each system is separately governed. The defender owns system 0.
             The other systems defend themselves on their own clock, and the
             defender cannot reset them: across the border it can only cut or
             revoke a relation. The wiring is identical in both scopes.

Run root resolves in this order: --out-root, then $CEMT_RUNS, then
C:\\cemt_runs on Windows or ~/cemt_runs elsewhere; the paper subfolder 4C is
appended, so runs land in <root>/4C/<timestamp>_p4c_<mode>_v0_13/.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import sys
import time
import types
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

VERSION = "0.21"
CODE_VERSION = f"PhDPaper4C v{VERSION} (2026-10-18)"
SPEC_VERSION = "Paper 4C Screening Methodology v0.3, pass 1 (ladder screen)"
ENGINE_BASE = "PhDPaper4B v0.23 engine and builders, lifted verbatim"


# ============================================================================
# Run-root resolution
# ============================================================================
def resolve_run_root(out_root: Optional[str] = None) -> str:
    if out_root:
        base = out_root
    elif os.environ.get("CEMT_RUNS"):
        base = os.environ["CEMT_RUNS"]
    elif sys.platform.startswith("win"):
        base = r"C:\cemt_runs"
    else:
        base = os.path.join(os.path.expanduser("~"), "cemt_runs")
    root = os.path.join(base, "4C")
    os.makedirs(root, exist_ok=True)
    return root


def new_run_dir(root: str, mode: str) -> str:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = os.path.join(root, f"{stamp}_p4c_{mode}_v{VERSION.replace('.', '_')}")
    d, i = base, 1
    while True:                       # two runs started in the same second must not share a directory
        try:
            os.makedirs(d, exist_ok=False)
            return d
        except FileExistsError:
            i += 1
            d = f"{base}_{i}"


# ============================================================================
# ==== MODEL BEGINS ====
# ============================================================================
# EMBEDDED FROZEN CORE cemt_core v0.8 (hash-checked at load)
# ============================================================================

EMBEDDED_SET_DIGEST = '97dbae4714b278aa322588f69291cf10637fc1aaeedd434eb7590d9edbea3a09'
EMBEDDED_HASHES = {
    "spec": "4974b27b3a40166707878e31ea3b85e455ca0611738b80b86aea94d6f47576c9",
    "relations": "8757d456ad184634d635264dd7b2439a254353a442e7b5d3c1ffdb82ac32860e",
    "network": "49539f8a4670547ccea64cc389ba4fd54bd3c2c28ba2e6856fc583d5bb7172b4",
    "layers": "a0721d50c60de60fea958b796e412e4b89f839aa74321516029f62c342f581a4",
    "step": "6520b76ac28c6de6b98ff7ccf0e3379eb80dfc98d59d0b6460e0dbe7e423c7a6",
    "__init__": "68fb08d9ed682904cdf8614f7dce8153480b7da8b9d324dd578ca56cc896a3df"
}
EMBEDDED_SOURCES = {
    'spec': (
        'eNq1W91y2ziWvtdTYJWLFWdkJnGSrV6lPDVqW5l2dWK7LHV3ulwphiYhiW2K1BCUbY3Le71vMu81T7LfOQABUJJ/stOtqk7LJHBw'
        'cH6/cwB1u93O4ejTRKhEFnGVlUItZZJNsySus7IQvbN4KSvxZhiEnc5pIcUiTuZZIfcqGafxZS7dxEoWqayUqEtR35TipqzyVA06'
        'QuyJei7F2bqeg2AlpxIjE1AqU5mLXiIXdZSUlQwLiXnVlXgp3DNVy2VgaRyVyRW4WWRJVe6pNV4uRC/lh5Fevi+UXMZVXEuxjJOr'
        'eCaDTmcyl2W1FnGRzMtKgZre1OuhEAWY2MvlNThJyiLNaNNqII6LWlbTGFz2joO+GN3KZMXyOIvr+U28Fr3PQR+E3Ge4wvaqrMYr'
        'yArj1nkZp1gzFdhmdi3BgMpqUa5qlaWSt1NXWZyGjp/vBR5XUkJIuRY/cwZ+iE1sjXfc/H+vnBoZKNGLIRGlWhzFYlZi2SImYV+W'
        'qyKNq3XwXnyIiz1wwawd0v+VUHW1SupVFediWZXgpc6kcoztg9rYDAEbk2yBf4dpvKw1l6DA22HeYRRxzZaRlItlWciiBqnOEaxK'
        'kXCxOWg2lanojeWyFvuv9v+LNHz02hdiJZc5xK/EWZVdZ7mcSZEV4mO8JjkRZ0f7DXfviH0ofJYlgjacQz2Zagl6WpX/kIW2uFCc'
        'lGKaSRinmMMUmdgboUUBkVjxVLC30fnxz6Mjmr9gQlYxvMO+KKCfSpDBLSQshmV29FY0hoqNVlJBCClbPLhK8hjSg13UTM8TPERe'
        'iZ68jZM6YEbw3ugTKl6WbgyklxVxDlXSthVzShyXUzgjtBeKCZGGH4skriqo0tAxu8YWmOkleWshSRMpvJLcR2B1UlJfLOdxUWPX'
        'vERfXEN5l1kO1QSGmCp5B9tbzAqINasl7aAqV7O53inYCTtdhJsOSzOKpisypygSGe2OhF+U2qCUGZPCkCAwpbBJM8g+6uvd6IGy'
        'WC2aESN810/r9TIrZs3zoyyp++JjpvDv6ZKWifNOx7xcxwv80RmfjQ6jn0fn4+PTE3Eguq/C1+C380Ls/X4fUCMWZWW2+vsS77Bw'
        'xGETy3qwsD4vGAxYcdCAjX6e9bng52IXdEmh65JYlTni56WCM4ekQ6J0fDIZnX8YHo5IUsf62ejz6PCnCaQXnQ0nP/wy/JXefdbv'
        'hj9Nfjg9P57wsyHJVfN6bnzqkP7axS//34ZI64KNZfQmHG1ei6q8UQi9Hzma90x6uFYmXMI9mJAJmYHeHqILDJXNxUXLPhk3RIjM'
        'Vms19cWRXEq2ccojqd7sbU0TcjGpVkoHDFi6gq0jGlj2brJaewBHaDZIiBrptayQq2qERqIF+ReSfU9sflwuwgZDBGKsT2TidJEp'
        'Cqma/RhMr6pEdsTjn5g8rQRDFWcVEFwtlzmChDgONSvw/AIS3PHZzoNtluDutTTsFE8xktl9ATHEYiFp4UzBb6sYmmBRGU6fIkUb'
        'ET0Yx6Hm/b2vrps5Qj8yL8tfqqdoOTMIPNl8Dhs11VWZR0hOhYzSrCKdgc8WAIBM+sK9m5bVIhRDnQ4VO9lTPBz3kn4WiH/97z/F'
        '517WX+ivw96i//dgsKl4lyce/Bi2c+icclBZTLMZYq9NQwu5uCTs9Nna9iOfIVt6XiZx7hvPe7NljQXkrayQ8J/kDDlrGG56Us8K'
        'L9Da++YtSkOwL2Q4C2Fd17AGONxqiQTytIvM4PicCqE+iNlMpiUoAO6wBBKpRKplU9iwBO+dMQUgpqqWMP36SR9RagU1AQPKGwIr'
        'QipCHplCnDH20GzxaX+DO9TEFSDeNf6oPO0Nsc18/Z5Nq1ZPu1uNGmAWtgL04enJyehwYjKni2fm7Q9DvP7Ir7SP2lmT89OP0dnH'
        '4ckoOjo+JxInfzMkdvnarnn468Po/HznRCd+ncpVE6wUbR7SIJzGiahnc8xYs67Em/BtH/+8CzqHH4fjcTT+6ezs4/FojGXumI9W'
        '8gqdDAYbIushQ/ZNybAxR0tmsC3mHjLnA3N2S21g19EEXkCvcAZ2VV2JsBBl+iRJJ9ABSA6ZjXsIz8KENhqGnet0CkFSWKHC0cvK'
        'jfTOT3/5ZsFZJBNavPFtUnQEtsDJt4nWEbJIpv9NgtxJ4N7iIMYtj+C176HCOF8r0ihDHMTO2NNIVpBpJ9ICtJPTI8ZmlB2724J5'
        'gdiKgLlmhILiCqUaJ1KeO/51PBl9otkaL3U351rde7O9ejMtF3FWeKSi0w+R/jZmqqXqbpEyGXp35WrldGRqlSH76I9AUw+CRki8'
        'BhuyMiU+lbYadvvtBN05oDAQF5S4AHEAi46LJF9RmVqUNx1T8Lwdvnz7/ct3tudBxSzt05Agi38v3gxt9lMcVsX56NPo6Hg4GbUj'
        'pn1MAgEhmWZITl1fxgooESW1BjiASXMZ5/V8jQy5LuIFCl6Unlz4jQND8ufTH0fR5Pyn8URTvS6vZFRTWu2yyqGttIpvPBDhwQHk'
        'JyxmQ+1TeUBz6WVeGJRq0ISpS1EzVNcyfS6pBZITGKOa9Hg4omBdrxRD0pkcsNI4qkMgz6OYl5hY6VjPMEVgiw1QGWqhHY9PPxot'
        'ZKrMfR1oIoqrfK2F/1TWXpUR+Xg0iVperyUPcB+1UlGj9fHk9HwU/Xw8Pv7++KOph4yqI1dn/xGF59gVfOXlbySD37v8/Kst0I23'
        '/s16snXN4XagCG0QVa5O0q+0HW21vGyUy9IBFbL8vWljRNYm8fKyLHOIGNBSsjY/xEBTeGBQ3UvxaXyGfxvI2NmxiRMovh1Zhtol'
        'ubgDYqJiBhBDwSN7rqUY7IjOyhR8x4XfFdW9UF09mjqyaXYJKkLXYhbroNQELYxY01AmZiIY8LwaeHXV3l+wK9QceAHICOwqq/cm'
        'wIGlaGlqOAyLdenGxExRgdKgmaQLNPhgmvPKMYNjCm7soIh5sYW8INagdTMBHiOnU4oo15LQVhN3yAZ4o4hk4JApGbNsx0lfw85y'
        '3DO7YatrreKNUNAomDoZBHMZ3dstLslhCw3It0S0aUQmtpi5e3W556pXXQP75KxwdpFx/DkSxnoVW1Z5Y6SskxB9i7SUWAKcTOt2'
        'zKLMDh25OgSQwWmIJMi0ONbk8jGuiJbtDVJ6NPEcegNNixayxTImfqZ5iXUPxOvw1a5gzHGUWLiR2WxeE+CuJIRHCanQbUkdkf8B'
        'NAFLpmbdBbT7BSS520d9yniV1xHVTmW1PiAVBLs8tgknba+lAwzCqkiY7HxbPSVu6+p2u/hqkkb11aaPpvIzPv3Vfv1KLqJnIbVI'
        'avd/te3Prw35iHn7aiKA7lN5XShEjtpi6GCzKdWk1Xm2HDQtWOozbcVSfgU31GjLDE2zKZ+71DvG27EeRmuJrRGEc7lmk+6JFYWH'
        'c81Qf/ODNlpuplKFFudb/vvCLu1BAzMeJl1D5xQLW22VGYS+HNgW7wUYJPs5IYDqwZU9jSN0UQzjqv6AdHukQRq1KDNoiiowd2rS'
        'bw5XAiQ/7uPTKREfSZjeOherNmHnnA7iS6iPjIZ6sntTPnABWXLNS+nyQEqnEYsM0aTOEgp54R+e6GmL46VMtHGSMxfJOqLzO52T'
        'oIP9jXBA78D2VGNcH/yZ0KRdig5zfBiZVtm0jrIiIcxceGHnVfjqOxPAp1kepTcyz9scvOPXi/h24/GrjkHcwAx0lKKSuUxXOecr'
        'r5XHNtPXJkZuQzZl2sov8N9dF3pAqdIdiIssVV/6AJSUm67jHI+u7k2nisdQ6w05H+n3VZ+BPj248khV0Gu5iMArzQUpJWWKr+re'
        'yRDc7emwYGj9j/jp7lUYXt3TOahMjcA0QR6hQOGOEmraF2EY3t+3YzTgQp4lWW2mfaKQnMU566TkamwtLldZnkbNYS02SOBgi5NF'
        'vGzM2KQ3hjjmYKt9hLtcqTmBCe2M1Kxo5K9C8QtBLDIuQ4fPF6knxkeqejFYSF1JfhwrmIEOPFqXAz75ueASkb49nExSvN2ZTJzT'
        'OgNv6jWObPEy1qDdt8X/5nEUbW/mMl8AkwIGQbgtk30bvjKnEkWCdFG0KGhrreNVFPuP3+gZ2WwRR7ct63/nvUlbb/w51fYaLyCS'
        'W0hvWUL9az7JVfMyZ13VTMvbbwP+qHUwz3KNVlse6ldyyGP6UBHGlcAmCdWExBKWxwvSe1yszXymr9VneWjtw5AHDm6FOLYug5jf'
        'IWpUC8Z5aSkJpTBcFb2Nw9YgNMTGstbYB5ZcrTQub4ljK5qKnra+ZtMOCb2wgpIp+fV1aS5SULc+q+Dmdo52l8DIcMYpAEiOI8Pr'
        'fmPtSoxu4VwZRToE0Er+fYVwpDTv2BbiYNTir51EDZkP/nb4wJ+dJStEc79jIGSczNs74jxjt8PFjqEH3V4ak3emK24f8Io+qAn6'
        'M6HxpnWhGvHrZH8lKRmQ6A+x8nevgNHhdMiIe3Yidc9FzzpUX8S9OgjEioLT5dpQIwr+AXdoDH+xzGWkBbBDQubYO4JyyxsqGhl6'
        'bneaXPCw7YctSBovLlP4647Zoe34fNkNWsG3izAN+hrXJQoDtnI+jEcVOIOFUwhEtKxkbo64WlZwwAbtmbxBWq3DevaC9yaSzpqo'
        'WvCZEJtrc3zpq/t1uzgjN43rnSHQVgGwF32k/NJehaH6SPFtEntPgy7DtOuliPbbClbvHHo46w0FhQcVcNvqe8QpoTtbtU5RG6Xc'
        '47Q+P4NW08y5jsEqV6CO2msecUnBko4+Wq/2H4nwmyWSDZYoUZqD2KafZoRHjkwtLQAY0/RojjqNDboF9p0GLmMlo3pJahF74vXL'
        '3us/b00MNkSmgRacRbVA1nc7DsDq+EqSZ26J2SAyp9MNcvsmpifLSCG2AmVt7aLJeOZKSmTksr0Ub7TEpmzTmNSZgGZfULpJcuqF'
        'tGktt8m0BkBIO0bsAgmX+QZEaF9d2Ceb36vkjLoGpMTxZKjBDKU8Mcxzc4GKPfeAXmtPG08GOhjyyAMOWiEeI2TXSAv2wWQ4sPWC'
        'eSp6nBIVFm8Odt/Asqb9jeYS5fKg7deWUqs9oF0eq24/dSy23/HLv5prZeumTYcYfUmnHTKfBoSksdzAhtRKYuECrIS/lVnRS9gp'
        'kz5DxEL0et1xl/BtPg0tlxu38R759LqTZjZt5FsmDpuJbq/IP9kUjAXUV+4WJXV5f/9CclIuzQlGc/Lwh5dzY7OQM2e/DUe3uSK+'
        'pEHq1m0o//KUUbNKqmxZe2OMcfldPM60rkv8VK+nue7RtIeoNfucObZpb+Y1bYjnzGUniWjVB/sKFHn464FBWXsqJsjBGIsLHip/'
        'PGoJvCHOiodali+shy71NSJzU0P7q2blGbciWn087GdVXcbmmh6fpQCvAaL3GSMbho3qHkSU7Qreu0DWghaLBhA3EW7QCpAPCt0f'
        'FHjRpukuPDixGRBsBaN29fbwyq1hxmgIbw0sLntwbjNAz6LKu+ksvN3vGGBKfibysrxaAef+vx21CZ9kARw9+/w1Ms7JsdSdVnA7'
        'H4GJ4yZHLu06LbNB/CrCLBUHB5bUllmZiOzumFQxlXY/yvWoqsqqZyYGHcugc/GonD7E6ebhEMcGYsUxa0mHjmJrbzO7t9kOamaD'
        'M7PB2SObmz20uVlrYxyH3Z4QV1xPkzfFfV23ClbHmNA2MsEF/W07qJ0drDCJkM7vnVhUSyo+yZ2imVVb45sld45vrWxO/0lwisVW'
        '8RWk1lu/Weyb+DVAXKpr3n/PxA0h6UACB26Ku05ogCvnmvOYz2MIN1O1ksuFQmWzWKJiWci4UJqcPTVkiGfGDRxhyOziS8e7CgjL'
        'I8HfsQE9ZG73Hf8ioplyUTRTNrzvi28auSwaC0fx8R8H/EDJ2j0M2hbSMB3GS0LvvW66opYdnZ3pkj1V3eAbnd87EqBEgOFm59u+'
        'srn8lG+XiDva7P1ArIqrgg6sPIp3Pv37Dd4qy5vLz601aRCXhwT8Kmvy8DtnzttcYlc8yeymkeVgZ7rc3pI9DrpzK97v/eXOrYmt'
        'dp+Ve6fdRiRaTsSWLwTilLbvIIbIdMuK0QS1SzffP7qp7c14M+82SN3r3hiT+jaeGC/Y4LIxOgjdiey/w9w8plXd/edvtR2KvKE7'
        'rYNz2WtoF1XYPpf68hxTf5ZdaPj8tHVMu3ebTISIUStsXGX6cJ2OKp9F6JF9GZoa4t158jAv2nq3erWFqa2wWO9xse5t58+NNUnS'
        '7TtxR6Oz0cnR6OTw14c0t+HEKHmGHnS0w/hyhDlbb5A1/9DlckV/A1ObpxvUGH2/11cX+CcqNXU+0r4+oqAniv0AURSYb65vOVBj'
        'WkiCAGHbjGPvl1YmbzbG8gcUf78OP30Uxy9Pf++Sj3JsRL+c6SU5/cKHzCFoDjd4U3je048b28hUc49Fv+jTmECDA37Q0XSp2ReR'
        'Ynp0g8IBvu2qkvuL1LPhkX3RrVBko4Qo6Y7uQXdVT/e+6wbUs556DYL4BhmWfrQTqngqI1quNw183rlCpSP0iI51epgRGN623+gj'
        'ogcYVBr4+y+cC2TpAeZfdLO0+8U1EvzqmN6HMyT0rv8Ue/TLZa8J4RXNbqr3EDO7XW+8y60HXhXd+9OfZoHDK5aQGw06F18Cj2kG'
        'BwdcT2N2ETjsYGfzkK2J1jkPLlpu0oSA7YDRxM6D6qLbfIf87K0Cet589+Xq3fXXMexA26+9cAASF137tvtlR3OnHaoMgVa0YiLt'
        'YTsp2WsLB1QeA5ywjOxTyInr5WDHVD5APjAz+I/uxqjABUorfitorQI73pOQS5/OeNwzf5FWF8LsoD3DvNu1j/ZRQ3ty692uyU1Y'
        'b9X6MDlLoRmAyXf3/kxudzaFvj+DXmyN9nqm7doeM+9awvbXtiM1vbZWuhvnRHTQv6VcbVLbpz99EQdbg/WNW1/LmxyYpxsL95/f'
        '+dn4XHhXjVt+7G+WGx+2reGLmt9syZpaHgfIqs4M+LZCX7zdb4bpvTd5kopT+kWoLfL068xVb4ONcvxnSi+6IO9mBc9r/2gdkFz8'
        'WXTfC9M2bggFW3nBJIJ0tVjqJKWn+yG+L9qJi5DvoLnr1vohqlSuN0CHIVi5vPwtaDUAvLSJd62r6hs4Aq81MPOne2uFmYrsnxsL'
        'eWTurgYNM9c6lFwhw5Od+bRixRmQqIQZXartBfePsc0d0Z3rXZjFbvVit7QSpnx5jBpft/hG7kk8W5w60XV2Q4qbZ0AKBybILHpm'
        'eTKMoC+mBBSrOrqSa6VPVoLO/wF7Ko0e'
    ),
    'relations': (
        'eNq1Wdtu48gRfedXVDQPIRGKsXeSfZDhRTSyjBUwsQ1Lk8xAEOg21bLopUhuk7Kt3fg9f7L/tV+SqmreWqQ89iwiDDQUu7q6Lqdu'
        '7V6vZ13LSORhEkMubiMJIl7CUqrwQS4hy9U2yLdKRJCqJJUqD2UG9pXARzj+4HiWdS7ifrLN7dCFIBJZ5gBAvN3cIkGygmWY5WEc'
        '5KBkIJGlyiBOlhJCyLZpGhG3fK2S7d0ahAUdnzvcFOPuQkQ+woNRso1zkk+mQolcRjsQOWS7LJcbUqCTlV7uJ6u+fsogkg8yQh1G'
        'Wv57VMEpqWdqK+FxjYcXArOwKALuUTst/o5UDJJ4GWrhIE86T2YO9x5cotlYDxGFGYqfIKt6fwZkVaJ18eAwWEOYdbILEqEyJM3X'
        'IkYv/Jk39pOSOXpvFcbM8gTeD9GJaCGy8wF2IgMBWbhBd6zCQLMgEBx/QLtvRIiCiW2+TlSIjNAdaLApa2+bBltL9EdOJil8i85u'
        '2aewhQuIimi7DOO7TpnuIcwzGa20B3JkTfv67DDciirFAToFNVcyk3GOMn1I8nUTpUJJOBtfT/41PoOVSjbMRZlYt5cyCDP6ffbe'
        '8eBChkikyO4CCFkbmeNPMkZcLK3ZWncyZmM/SNjIAN0QZhvSFYWG5DH2YBrIWKgwsUpKPGKD7iY3IESTGLFTAp/kagTaT3FyS2QE'
        '6DUGGq1b+3KnSRKhz36RmUsGxtNyfYoL8gllRoSBSpIcNReBfj+6giwVMcXsGam1QYxgcAaAIKwdH6IpkuAnqQbkfJSY2OcIAjKL'
        'i1GGgZPmLFMNOPx3fwIrEUZbNHq4WoERUatEQZZskJVn9TDhWOwO319tUWPp+4DYS1SOdo6TnDlmBU2QRJEMdHAURAhusY3yZRjk'
        'mmYpcsFpQdY05StNke9SxFm5eIY7XfiIurswlfg126aRLA70slQGJeXo43A69aefrq4+TsZTtGCJZNxOQHShTJ0jOsytvD5FJpbl'
        'jy4vzuAUfu1NeoN6sze5mI2vz4ejsQu9z8bK+PN49Gk2ubzwr4azH/89/IIUQ4Ni+Gn24+X1ZPbl2bKsf9R68nclznXyOOCwKgNx'
        'QADjN2Uert9U8dk4pyDV3HxmPjCVZQoOx4E2RslrJRWieAC3iFB+d4coT/k4+A9cJDGaek/cGWFaC4zeRWBQ9vJ9mxKAC+SRgWFa'
        'Z1DlDCLRPjtlwmrhHVzGGO7JIyfVOgcZSaCqQZRPKBeBjUnvvfe3v773/t445R0xiDUQYXICFPExJqLPJ1jgFL3HrRQnCqMyjQSe'
        'PAF7SPkpSgIMxWZJelfskUsXk1peCrF0TkrztbkNPVNj1AsdQhieN3y+QCPMFxUlhZ2igCbDeKXS2cBIuEQUEJEJ9rnyTPcvBq08'
        'XUniiTSV8dJuiGIrr8SeC8RLo84FDop5sHA70/7Bz744GhYeA9BPVrZy3sywwioJyCB1nBYPw/Pozmy3wZqgQkTkLwhlXO1vJDU7'
        '2TpMQSw3VAFuqRI9il273IarliZwempGlocWuhiPKA0MuvuYl+1e27rpg2+0+//F9q+w/7uueo+QF7p/qAK3KLjNAE+K1sGIg7iK'
        'A9rfFQPIwC27CSK27c6MHXshdp5qJQL5KrXtF7N77MknGWzZtqnI1wiat3KtKgJxK/u0neMMusBX6PcNuDooFBpk6Rbf2oiH0HxY'
        'MS4g3sXlGRr4XEQZNsBUKBAPlgZDHz9ly409ZsYv3vqpCoxmVJQXoyBqFRqF0IH+D9QlzHGxkQKVxM4lhl/rCGtk29KMh6Jfn0dx'
        'Xz1Th8kRUYAY1+jHs2XKTC21f7vzK8IuHVhkanLmjX6lVKFDB0xluopqq9Tpo+jcdHUoWT0bLimGv29yh+GSlYh9miKLkt9sW9yX'
        'G5GiqcDSR/+1MdbsUUxaNlTYjIZ6SMWuzdrPgYWvvuJodnKFCnRk9aydXPH5U71kMCAye69GYOVhwenojvphvnHa7Io82uSiX+Fm'
        'fqj3PO8DJJJxBYrMsfZd5vNEwo6rkcduq5/QyE3k4a7BYTq0faPHt+nL6cjlZeN3KKErxq0BlXbaQ0nmlLoWcxV4DyLaSjqeeZeI'
        '1JnNtPCpCkwj13x6WZL1DjBhS5/qZDf9Mp2N/+lfnvv6aXqQYY4zUdTN0tn3FVsMV83EOfoDEWpEaXA4Qr+aRGkeqB2AYyBfsNCs'
        'eFMyuyGEUoPO43F9w3JD/G6ost+UB914NEhWlas0TjuH4c6WlaqIJBxxgBDGM4ei4dhqautjsXl1juU5UgPZgN2iSDsLQ/1zxKgU'
        'wbpuXVywt3H487Zqbxqpr7xbw+zC1wWsZ2MmyPliQj7hsE82i+legtpSFySWUz7esFgdgm9RgNLis9UeHaoJ0syZmBppInlVbXx7'
        'fVwYPOorp9PuskynPu9navZ7uVP7v50k1BHypO3zo0VnBgnIMLY6ao48R95LSZmcMjjMi6fkPdDiognNvbzLw2DDg/zVcK7pUROL'
        'wygCuwm6ZvgU+/fUoYs5JTm1rJNoWTuUXFVBlIOMLsyWGOhIj601pWsPNay6e9KgXwR744ZSPtH9IA3JWUh3fXwbRZNxMQLgEPYQ'
        'igg36Xuqehao7qXqoXnWnPqrkhoInLXpFjlhPZYyzrB1xtcx3BI9XQLhctoo0HqvPSlngP7tri+W9/gUB7iTrqVxPkr5clZi15Xm'
        '8N3Rd99Dec/otKPwjY5rz/ivq4eBC+swr0jL5MZlxAvpOtzunhl4V8ZXFdw9kIPxHQYDtTC0v3ucQOXKQcLW9NWYwKLMjxeO81WU'
        's0m7ik67e0PLXlR/eLA7QOxAKkLMEGQOfcFulh5BMDAcVBWMjX2srzFxktb/DEvqWOT0nDV7PsdUpkAYt/Dkza6uiXqgWieNqMHe'
        'Oue4omEZwNGhfsdM1X4puqbcl910oj630RX9hUrjnlk0kTmj1ffYgUjFbRhRRJV/MBq6MP7Zg+8hRudkHGzF/Rk3CcaMVjHya0YF'
        'DgjhPsKugkGrt5jA7//9DT7z91AnKLZB+YeE4s9K9DPYKs5LRQZia3RhAFONzeWi0WcUgtCo5MAPhSPMkrg/wm42Qu3++LxUMDIB'
        'VJuAM2u210kjcpyOy8HqPtFqjU0IAD0nvIQCc1DqxT4x6w2gMhb93rvV6NE7CgPmjsQsoD5znxQrDqFUhZghDb4N8O7v2Ygnv2iU'
        'cQf+su1283wweX79CqYw6+lRS1ja7z+G+boBWxSBMkiL6fFBCTiR8KvOMGDxG0c/W/8DtgnnBw=='
    ),
    'network': (
        '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'
        'Cov0lb25NYONnF+BkFRE32LeG+GXOjz4L+/R8qU='
    ),
    'layers': (
        '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'
    ),
    'step': (
        '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'
    ),
    '__init__': (
        'eNptUEFqwzAQvPsVi04JCBPaSyn0EIwphTYpSehVKPa4iMhas5JT2tfXduxTq9NoNDszWqVUUb6dqGLBIzXCPwgkaCAIFci1nUeL'
        'kGxyHKhhoXfbQeh+S6vrJr+jeIFH4rDOlVLZYNBSHjtU4yhLotWxQrDi+DiQmnZcQ9MBfjLU9MxXSLBDlqaCQ+0mOqO/Z5kpvI1R'
        '0yuu8Jq25xt7c/dsaxMnWPdtd4P/mY0PZixralel9dxb5oi4lF8yT/bsMYsC0hfLZZGce+drM5OaPhEgNmGKXtaR0C1y6YPhAJPE'
        '2aH+eI3zgjTFvm0HFIddVOMvXfNtKvbedhFZsT+U5qM8HF/2O3oitckfVPYLdfqVVA=='
    ),
}


# ============================================================================
# Embedded frozen core loader
# ============================================================================
def _load_embedded_core():
    """Decode, hash-check and execute the embedded cemt_core v0.8 modules,
    registering them in sys.modules as an in-memory package. Abort on mismatch."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        stub = types.ModuleType("yaml")
        def _no_yaml(*a, **k):
            raise RuntimeError("PyYAML not installed; core YAML loaders unavailable")
        stub.safe_load = stub.safe_dump = stub.load = stub.dump = _no_yaml
        sys.modules["yaml"] = stub
    pkg = types.ModuleType("cemt_core")
    pkg.__path__ = []
    pkg.__package__ = "cemt_core"
    sys.modules["cemt_core"] = pkg
    report = {}
    for name in ("spec", "relations", "network", "layers", "step", "__init__"):
        src = zlib.decompress(base64.b64decode(EMBEDDED_SOURCES[name]))
        report[name] = hashlib.sha256(src).hexdigest() == EMBEDDED_HASHES[name]
        code = compile(src, f"<embedded cemt_core/{name}.py>", "exec")
        if name == "__init__":
            exec(code, pkg.__dict__)
            continue
        mod = types.ModuleType(f"cemt_core.{name}")
        mod.__package__ = "cemt_core"
        sys.modules[f"cemt_core.{name}"] = mod
        setattr(pkg, name, mod)
        exec(code, mod.__dict__)
    if not all(report.values()):
        bad = [k for k, v in report.items() if not v]
        raise SystemExit("EMBEDDED CORE DIFFERS from freeze record: " + ", ".join(bad)
                         + "; run not citable against the frozen substrate.")
    return pkg, report


_CORE_PKG, _FREEZE_REPORT = _load_embedded_core()

# NOTE: cemt_core is created in memory by _load_embedded_core() above; it is
# not a package on disk, so static analysers (Pylance/Pyright) will warn
# "Import could not be resolved". The import is correct at runtime. The
# pyright: ignore / type: ignore markers suppress that false positive.
from cemt_core.spec import (Condition, Governance, Node, Relation,  # type: ignore # noqa: E402
                            RelationClass, ScenarioSpec, RateSpec)
from cemt_core.network import build_network, NetworkState  # type: ignore # noqa: E402


# ---------------------------------------------------------------------------
# Stage constants
# ---------------------------------------------------------------------------
T1_INTERFACE = 1
T2_AUTHORITY = 2
T3_EXECUTION = 3
COMPROMISED = 4          # result state
RESIDENCE = 3            # ticks from admission to compromise when all checks pass


@dataclass
class Resident:
    """A payload in progress at a node: which stage it has reached, and its reference."""
    stage: int           # 1,2,3 = the stage whose check it must next pass
    reference: int       # campaign/version signature
    via: int             # supplier node index that delivered it
    needs: Tuple[str, ...] = ("X", "A")   # standing conditions still required


# Per-class standing conditions the RECEIVER must hold (the ones the relation
# does not itself supply), matching frozen v0.8 layer2 path_capability:
#   connection  supplies I  -> receiver needs standing X and A
#   channel     supplies I,X (route; X assessed on admission) -> needs A
#   directing   supplies I (plane must be owned) -> needs standing X and A
#   conferring  no push
CLASS_NEEDS = {
    RelationClass.CONNECTION: ("X", "A"),
    RelationClass.CHANNEL: ("A",),
    RelationClass.CONTROL_PLANE_DIRECTING: ("X", "A"),
}


@dataclass
class Config:
    # rhythms (ticks)
    horizon: int = 1000
    obs_interval: int = 5           # O: status-check cadence
    tactical_cycle: int = 5         # C_T: clean / isolate
    strategic_cycle: int = 20       # C_S: block push / cut  (H1 varies this)
    attacker_cycle: int = 5         # C_R
    block_delay: int = 2            # push lag added to the strategic boundary
    # doses (budget per cycle)
    def_tactical_budget: int = 1
    def_strategic_budget: int = 1
    atk_budget: int = 1
    # which defender rules are active
    defender_tactical: bool = True
    defender_strategic: bool = True
    strategic_revoke: bool = False   # v0.8 revoke_trust: disable an owned directing
                                     # plane whose member is observed compromised
    strategic_harden: bool = False   # remove native I/X on clean nodes adjacent to compromise
    attacker_on: bool = True
    # gated recovery (4B mechanic): the defender may RESET a node only through a
    # clean controller that holds Authority over it; otherwise it can only
    # ISOLATE. Makes total compromise absorbing. OFF for Stage 0 / archetypes so
    # they reproduce 3A's free external reset exactly.
    gated_recovery: bool = False
    # observation latency to the master, in ticks, before it can detect a reference
    detect_latency: int = 1
    # --- Monte Carlo / drift mechanics (4B) ------------------------------
    # randomised-policy null: actors use the same budget and information but pick
    # targets at random, to test whether the rule-based policy structure adds
    # anything over chance. OFF = rule-based (the real policy).
    random_policy: bool = False
    # defender success probability (eta_0): a fix/clean/block takes hold on a node
    # with this base probability, not with certainty. <1 makes the run genuinely
    # Monte Carlo. 1.0 reproduces the deterministic-success behaviour.
    def_success_prob: float = 1.0
    # epistemic drift degrading CONTROL (4B; observation stays perfect, that is 4C):
    # delta accumulates with compromise and the defender's success probability
    # falls as eta_0 * exp(-drift_alpha * delta), mirroring the frozen core's
    # eta = eta_0 e^{-alpha delta}. drift_rate sets how fast delta grows with the
    # compromised share. OFF (alpha or rate = 0) = no drift.
    drift_alpha: float = 0.0
    drift_rate: float = 0.0
    # --- austere 4B (v2 spec): time-and-adaptation ------------------------
    # strategic adaptation = reconfiguring the GRAPH (cut compromised->clean
    # bridges), distinct from tactical node-state cleanup. adaptation=False is
    # the fixed-posture baseline (never reconfigure); True refreshes the
    # structure on the strategic cadence. strategic_reconfigure gates the
    # mechanic itself (off => the old block/revoke/harden strategic path runs).
    strategic_reconfigure: bool = False
    adaptation: bool = False
    # operational tempo: how often the fleet-wide block (signature push) fires.
    # Independent of tactical_cycle (clean) and strategic_cycle (restructure) so
    # the two tempos can be swept separately. 0 => fall back to tactical_cycle.
    block_cycle: int = 0
    # order-sensitivity test: swap the Authority and Execution checks in the
    # acquisition sequence (admission stays first, and the block still lands at
    # the second stage). False = default order (Authority then Execution).
    swap_ax: bool = False
    # blind-lever experiment: structural action variant on the structural cadence.
    # "" = use the normal adaptation path; "blind" = cut k edges by graph structure
    # only; "informed" = cut k observed compromised->clean edges; "none" = no
    # structural action. blind_k is the shared edge-cut budget.
    blind_mode: str = ""
    blind_k: int = 5
    seed: int = 4101


@dataclass
class Record:
    tick: List[int] = field(default_factory=list)
    compromised: List[int] = field(default_factory=list)
    in_progress: List[int] = field(default_factory=list)
    isolated: List[int] = field(default_factory=list)
    master_held_by_attacker: List[int] = field(default_factory=list)
    n_blacklisted: List[int] = field(default_factory=list)
    n_references_live: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine4B:
    def __init__(self, spec: ScenarioSpec, cfg: Config,
                 master: Optional[str] = None,
                 source: Optional[str] = None,
                 source_trusted: bool = False,
                 deterministic: bool = False):
        self.cfg = cfg
        self.deterministic = deterministic or bool(getattr(spec, "deterministic", False))
        self.rng = np.random.default_rng(cfg.seed)
        self.net: NetworkState = build_network(spec, np.random.default_rng(cfg.seed))
        # directing control-plane ownership (a plane is owned once its controller
        # is compromised); mirrors frozen layer3.
        self.owned_plane: Dict[str, bool] = {g: False for g in self.net.control_planes}
        self.owned_at: Dict[str, int] = {}
        self.ever_seen_comp: Set[int] = set()
        n = self.net.N
        self.n = n
        self.master = self.net.index[master] if master else None
        self.source = self.net.index[source] if source else None
        self.source_trusted = source_trusted
        self.est = ~self.net.external

        # dynamic state
        self.state = np.zeros(n, dtype=np.int8)          # 0 healthy, COMPROMISED when fallen
        self.comp_ref = np.full(n, -1, dtype=int)        # reference held by a compromised node
        self.resident: Dict[int, Resident] = {}          # node -> in-progress payload
        self.isolated = np.zeros(n, dtype=bool)
        self.rel_enabled: Dict[RelationClass, np.ndarray] = {
            rc: self.net.access[rc].copy() for rc in RelationClass
        }
        # adjacency lists per class (supplier -> set of receivers), maintained
        # on disable, so propagation does not recompute flatnonzero every tick
        self.adj: Dict[RelationClass, Dict[int, Set[int]]] = {}
        for rc in RelationClass:
            d: Dict[int, Set[int]] = {}
            rows, cols = np.nonzero(self.rel_enabled[rc])
            for i_, j_ in zip(rows.tolist(), cols.tolist()):
                d.setdefault(i_, set()).add(j_)
            self.adj[rc] = d
        # directing-plane lookup: (controller, member) -> group, built once
        self.plane_of: Dict[Tuple[int, int], str] = {}
        # member -> set of controller indices that hold Authority over it (directing
        # and conferring planes). Used to decide whether a clean controller can
        # recover a node (gated recovery) and whether the attacker can re-establish.
        self.controllers_of: Dict[int, Set[int]] = {}
        for g, (ctl, members) in self.net.control_planes.items():
            for m in members:
                self.plane_of[(int(ctl), int(m))] = g
                self.controllers_of.setdefault(int(m), set()).add(int(ctl))
        for g, (iss, members) in getattr(self.net, "conferring_planes", {}).items():
            for m in members:
                self.controllers_of.setdefault(int(m), set()).add(int(iss))
        self.last_reset: Set[int] = set()   # nodes reset on the previous tactical action
        self.delta = 0.0                     # epistemic drift accumulator
        self.severed: Set[tuple] = set()     # edges the defender permanently cut
                                             # (reconfiguration); the attacker
                                             # cannot re-open a segmented edge
        self._pol_rng = np.random.default_rng(cfg.seed + 99)  # policy randomisation (null)
        self.blacklist: Dict[int, Set[int]] = {j: set() for j in range(n)}   # per-node refs denied
        self.pending_blocks: List[Tuple[int, int]] = []  # (arrival_tick, reference) fleet pushes
        self.attacker_owns_master = False
        self.atk_reference = 0                           # current campaign reference
        self._next_ref = 1
        self.first_seen_ref: Dict[int, int] = {}         # reference -> tick master could first see it
        self.rec = Record()

        # authority revoked on nodes (condition removal): blocks T2 structurally
        self.authority_revoked = np.zeros(n, dtype=bool)
        # hardened: interface/execution removed
        self.iface_removed = np.zeros(n, dtype=bool)
        self.exec_removed = np.zeros(n, dtype=bool)

    # ---- helpers ----------------------------------------------------------
    def _has_I(self, j: int) -> bool:
        return bool(self.net.sup_I[j]) and not self.iface_removed[j]

    def _has_X(self, j: int) -> bool:
        return bool(self.net.sup_X[j]) and not self.exec_removed[j]

    def _has_A(self, j: int) -> bool:
        return bool(self.net.sup_A[j]) and not self.authority_revoked[j]

    def _compromised_mask(self) -> np.ndarray:
        return self.state == COMPROMISED

    def _source_reference(self, tick: int) -> int:
        """A trusted source mints a new reference every update (strategic) cycle, free."""
        if not self.source_trusted:
            return self.atk_reference
        version = tick // max(1, self.cfg.strategic_cycle)
        ref = 10_000 + version
        self.first_seen_ref.setdefault(ref, tick)
        return ref

    # ---- propagation (one tick) ------------------------------------------
    def _update_plane_ownership(self, tick: int):
        """A directing plane is owned once its controller is compromised
        (mirrors frozen layer3; member-takeover is stochastic, out of Stage 0).
        Records the tick ownership began, for rollout-delay honouring."""
        for g, (ctl, members) in self.net.control_planes.items():
            if not self.owned_plane.get(g, False) and self.state[ctl] == COMPROMISED:
                self.owned_plane[g] = True
                self.owned_at[g] = tick

    def _rollout_ready(self, g: str, j: int, tick: int) -> bool:
        """Honour the directing plane's rollout schedule (frozen layer2): a member
        is pushed only once ticks-since-ownership exceeds its delay. No schedule
        means immediate."""
        delays = self.net.rollout_delays.get(g, {})
        if not delays:
            return True
        since = tick - self.owned_at.get(g, tick)
        return since >= delays.get(int(j), 0) + 1

    def _needs_met(self, j: int, needs: Tuple[str, ...]) -> bool:
        ok = True
        if "X" in needs:
            ok = ok and self._has_X(j)
        if "A" in needs:
            ok = ok and self._has_A(j)
        if "I" in needs:
            ok = ok and self._has_I(j)
        return ok

    def _plane_group_of(self, i: int, j: int) -> Optional[str]:
        return self.plane_of.get((i, j))

    def _disable_relation(self, rc: RelationClass, i: int, j: int):
        """Disable one relation and keep the adjacency list in step."""
        if self.rel_enabled[rc][i, j]:
            self.rel_enabled[rc][i, j] = False
            s = self.adj[rc].get(i)
            if s is not None:
                s.discard(j)

    def _deliver(self, tick: int):
        """Compromised, non-isolated nodes (and a persistent source) deliver on
        enabled relations. A delivery of class rc creates or advances a resident
        payload at the receiver, which must still pass the standing conditions rc
        does not supply (CLASS_NEEDS), spread over the stage ticks. Uses the
        maintained adjacency lists so it does not scan the matrix each tick."""
        self._update_plane_ownership(tick)

        def _offer(i: int, j: int, rc: RelationClass, ref: int):
            if self.state[j] == COMPROMISED or self.isolated[j]:
                return
            if rc == RelationClass.CONTROL_PLANE_CONFERRING:
                return  # conferring plane makes no push
            if rc == RelationClass.CONTROL_PLANE_DIRECTING:
                g = self.plane_of.get((i, j))
                if g is None or not self.owned_plane.get(g, False):
                    return  # plane not owned -> no directing push
                if not self._rollout_ready(g, j, tick):
                    return  # member not yet in the rollout window
            self._arrive(j, ref, i, rc, tick)

        comp_idx = np.flatnonzero(self.state == COMPROMISED)
        for i in comp_idx.tolist():
            if i == self.source or self.isolated[i]:
                continue  # source delivers only via its own block (rotating ref)
            ref = int(self.comp_ref[i]) if self.comp_ref[i] >= 0 else self.atk_reference
            for rc in RelationClass:
                for j in self.adj[rc].get(i, ()):  # maintained adjacency
                    _offer(i, j, rc, ref)

        if self.source is not None and not self.isolated[self.source]:
            sref = self._source_reference(tick)
            for rc in RelationClass:
                for j in list(self.adj[rc].get(self.source, ())):
                    _offer(self.source, j, rc, sref)

    def _arrive(self, j: int, ref: int, via: int, rc: RelationClass, tick: int):
        """Create or advance a resident payload at node j for class rc."""
        res = self.resident.get(j)
        if res is None or res.reference != ref:
            res = Resident(stage=T1_INTERFACE, reference=ref, via=via)
            res.needs = CLASS_NEEDS[rc]
            self.resident[j] = res
        else:
            # keep the least demanding admissible path seen this campaign
            if len(CLASS_NEEDS[rc]) < len(getattr(res, "needs", ("X", "A"))):
                res.needs = CLASS_NEEDS[rc]

    def _advance_residents(self, tick: int):
        """Each resident attempts its current stage check this tick. Stages take
        one tick each; checks for conditions the delivering class did not supply.
        T2 consults the blacklist (the block lands here)."""
        done = []
        for j, res in list(self.resident.items()):
            if self.isolated[j] or self.state[j] == COMPROMISED:
                done.append(j)
                continue
            needs = getattr(res, "needs", ("X", "A"))
            # which condition is checked at the second stage vs the third. Default
            # is Authority then Execution; swap_ax flips them for the order test.
            # The block always lands at the second stage (the operational point).
            first_cond, second_cond = ("X", "A") if self.cfg.swap_ax else ("A", "X")
            checks = {"A": self._has_A, "X": self._has_X}
            if res.stage == T1_INTERFACE:
                # admission: the delivering relation supplies reach; a fresh draw
                # each tick (faithful to v0.8 per-step redraw), certain if det.
                if self._admit(j):
                    res.stage = T2_AUTHORITY
            elif res.stage == T2_AUTHORITY:
                if res.reference in self.blacklist[j]:
                    continue  # blocked reference denied at the second stage
                if (first_cond not in needs) or checks[first_cond](j):
                    res.stage = T3_EXECUTION
                else:
                    done.append(j)  # this condition structurally absent: cannot complete
            elif res.stage == T3_EXECUTION:
                if (second_cond not in needs) or checks[second_cond](j):
                    if self._execute(j):
                        self.state[j] = COMPROMISED
                        self.comp_ref[j] = res.reference
                        done.append(j)
                else:
                    done.append(j)  # remaining condition absent
        for j in done:
            self.resident.pop(j, None)

    def _admit(self, j: int) -> bool:
        if self.deterministic:
            return True
        p = float(self.net.x_prob[j] * self.net.a_prob[j])
        return bool(self.rng.random() < min(max(p, 0.0), 1.0))

    def _execute(self, j: int) -> bool:
        return True  # given admission and authority, execution is deterministic

    # ---- super-node push --------------------------------------------------
    def _master_push(self, tick: int):
        """If the attacker owns the master, its directing authority pushes the
        campaign reference to all members (admitted certain)."""
        if self.master is None or not self.attacker_owns_master:
            return
        for rc in (RelationClass.CONTROL_PLANE_DIRECTING,):
            for j in np.flatnonzero(self.net.access[rc][self.master]):
                j = int(j)
                if self.state[j] == COMPROMISED or self.isolated[j]:
                    continue
                # certain admission; still subject to blacklist at T2
                if self.atk_reference in self.blacklist[j]:
                    continue
                self.state[j] = COMPROMISED
                self.comp_ref[j] = self.atk_reference

    # ---- defender actions -------------------------------------------------
    def _observe(self) -> np.ndarray:
        comp = self._compromised_mask()
        return comp & self.net.visible & self.est & ~self.isolated

    def _success(self) -> bool:
        """Does a defender fix take hold this attempt? Base probability eta_0,
        degraded by epistemic drift: eta_0 * exp(-drift_alpha * delta)."""
        p = self.cfg.def_success_prob
        if self.cfg.drift_alpha > 0:
            p *= float(np.exp(-self.cfg.drift_alpha * self.delta))
        if p >= 1.0:
            return True
        return bool(self._pol_rng.random() < max(0.0, p))

    def _order(self, cands, key):
        """Rule-based priority order, or a random shuffle under the null policy."""
        cands = list(cands)
        if self.cfg.random_policy:
            self._pol_rng.shuffle(cands)
            return cands
        return sorted(cands, key=key)

    def _clean_controller_governs(self, j: int) -> bool:
        """A clean, non-isolated controller holds Authority over j, so the
        defender has a path to recover it. The management master governs every
        estate node through the mgmt plane; other planes govern their members."""
        if self.master is not None and self.state[self.master] != COMPROMISED \
                and not self.isolated[self.master]:
            return True
        for c in self.controllers_of.get(j, ()):
            if self.state[c] != COMPROMISED and not self.isolated[c]:
                return True
        return False

    def _reset_node(self, j: int):
        self.state[j] = 0
        self.comp_ref[j] = -1
        self.resident.pop(j, None)
        self.last_reset.add(j)

    def _isolate_node(self, j: int):
        self.isolated[j] = True
        self.resident.pop(j, None)

    def _tactical(self, tick: int):
        obs = self._observe()
        budget = self.cfg.def_tactical_budget
        self.last_reset = set()
        if not self.cfg.gated_recovery:
            # 3A-faithful mode: free reset of observed compromised nodes
            order = self._order(np.flatnonzero(obs).tolist(),
                                key=lambda j: -len(self.adj[RelationClass.CONNECTION].get(int(j), ())))
            for j in order:
                if budget <= 0:
                    break
                if self._success():          # stochastic success (Monte Carlo)
                    self._reset_node(int(j))
                budget -= 1                   # the attempt consumes budget either way
            return
        # 4B gated recovery: isolate a captured super node first; recover nodes a
        # clean controller still governs; isolate the rest (cannot be recovered).
        comp_obs = [int(j) for j in np.flatnonzero(obs)]
        # 1. isolate a compromised master/hub (super node) to stop its push
        supers = [self.master] if self.master is not None else []
        for sn in supers:
            if budget <= 0:
                break
            if sn is not None and self.state[sn] == COMPROMISED and not self.isolated[sn]:
                self._isolate_node(sn)
                budget -= 1
        # 2. recover governed nodes, highest connection degree first (stochastic)
        recoverable = self._order([j for j in comp_obs if self._clean_controller_governs(j)],
                                  key=lambda j: -len(self.adj[RelationClass.CONNECTION].get(j, ())))
        for j in recoverable:
            if budget <= 0:
                break
            if self._success():
                self._reset_node(j)
            budget -= 1
        # 3. isolate what cannot be recovered (no clean controller path)
        if budget > 0:
            for j in comp_obs:
                if budget <= 0:
                    break
                if self.state[j] == COMPROMISED and not self.isolated[j] \
                        and not self._clean_controller_governs(j):
                    self._isolate_node(j)
                    budget -= 1

    def _note_observed(self):
        """Latch nodes ever observed compromised (the defender remembers)."""
        for j in np.flatnonzero(self._observe()):
            self.ever_seen_comp.add(int(j))

    def _revoke_trust(self, tick: int):
        """v0.8 revoke_trust: for any owned directing plane with an observed
        compromised member, disable that plane's directing relations (the plane
        ceases to supply I / direct A), so a persistent controller can no longer
        re-deliver. Does not require the management master; the defender acts on
        planes inside its estate. Budget: one unit per plane revoked."""
        budget = self.cfg.def_strategic_budget
        for g, (ctl, members) in self.net.control_planes.items():
            if budget <= 0:
                break
            mem_idx = [int(m) for m in members]
            seen = any(m in self.ever_seen_comp for m in mem_idx)
            if self.owned_plane.get(g, False) and seen:
                # disable this controller's directing relations to its members
                for m in mem_idx:
                    self._disable_relation(RelationClass.CONTROL_PLANE_DIRECTING, int(ctl), m)
                self.owned_plane[g] = False
                budget -= 1

    def _strategic(self, tick: int):
        """Master detects references of observed compromises and schedules a
        fleet-wide block after block_delay; also may cut a source relation."""
        if self.cfg.strategic_revoke:
            self._revoke_trust(tick)
        if self.master is None:
            return
        # master must not itself be attacker-held to push defensive blocks
        if self.state[self.master] == COMPROMISED:
            return
        obs = self._observe()
        budget = self.cfg.def_strategic_budget
        refs_seen = {int(self.comp_ref[j]) for j in np.flatnonzero(obs) if self.comp_ref[j] >= 0}
        for ref in sorted(refs_seen):
            if budget <= 0:
                break
            self.pending_blocks.append((tick + self.cfg.block_delay, ref))
            budget -= 1
        # with remaining budget, cut a relation from a persistent source if known
        if budget > 0 and self.source is not None:
            for rc in RelationClass:
                live = sorted(self.adj[rc].get(self.source, ()))
                if live:
                    self._disable_relation(rc, int(self.source), int(live[0]))
                    budget -= 1
                    break
        # harden: remove native Execution Pathway on a clean node adjacent to a
        # compromised supplier, blocking that node as an onward step (patching /
        # attack-surface reduction). Budget: one unit per node hardened.
        if self.cfg.strategic_harden and budget > 0:
            comp = self._compromised_mask()
            for i in np.flatnonzero(comp).tolist():
                if budget <= 0:
                    break
                for rc in RelationClass:
                    for j in list(self.adj[rc].get(i, ())):
                        if budget <= 0:
                            break
                        if self.state[j] != COMPROMISED and not self.isolated[j] \
                                and not self.exec_removed[j]:
                            self.exec_removed[j] = True
                            budget -= 1

    def _reconfigure(self, tick: int):
        """Austere 4B strategic adaptation (doctrine v2): cut edges from a
        compromised node to a clean, non-isolated node, across ALL relation
        classes (containment by disconnection), budget-limited. Changes from v1:
          - master- and directing-plane edges are cut first (the pivot: once a
            controller is captured it spreads through its directing plane, which
            CONNECTION-only cutting left untouched);
          - cuts are PERMANENT (recorded in self.severed), so the attacker cannot
            re-open a defensively segmented edge. You do not un-segment.
        Still a deterministic STRUCTURAL action: it edits the graph, it does not
        clean node state. Only edges OUT of compromised nodes are cut, so a clean
        controller's recovery channel is never severed."""
        budget = self.cfg.def_strategic_budget
        comp = self._compromised_mask()
        bridges = []
        for rc in RelationClass:
            for i in np.flatnonzero(comp).tolist():
                for j in list(self.adj[rc].get(i, ())):
                    if self.state[j] != COMPROMISED and not self.isolated[j]:
                        touches_master = self.master is not None and (i == self.master or j == self.master)
                        directing = (rc == RelationClass.CONTROL_PLANE_DIRECTING)
                        prio = 0 if (touches_master or directing) else 1
                        bridges.append((prio, rc, int(i), int(j)))
        bridges.sort(key=lambda t: t[0])
        for _prio, rc, i, j in bridges:
            if budget <= 0:
                break
            self._disable_relation(rc, i, j)
            self.severed.add((rc, i, j))       # permanent segmentation
            budget -= 1

    def _block(self, tick: int):
        """Tactical/operational: the master detects the references behind
        observed compromises and schedules a fleet-wide blacklist (signature /
        IOC push) after block_delay; a node holding the blacklisted reference
        rejects re-delivery. Not a structural change, so it is tactical, and it
        runs on the fast tactical cadence regardless of adaptation."""
        if self.master is None or self.state[self.master] == COMPROMISED:
            return
        obs = self._observe()
        budget = self.cfg.def_tactical_budget
        refs_seen = {int(self.comp_ref[j]) for j in np.flatnonzero(obs) if self.comp_ref[j] >= 0}
        for ref in sorted(refs_seen):
            if budget <= 0:
                break
            self.pending_blocks.append((tick + self.cfg.block_delay, ref))
            budget -= 1

    def _strategic_adapt(self, tick: int):
        """Austere 4B strategic adaptation, doctrine v3: ALL structure-changing
        actions, since edge-cutting alone is too weak against a persistent
        source. Three moves, all permanent where they sever structure:
          (1) cut the source: sever the persistent supplier's delivery edges,
              so the re-tooling vendor can no longer re-inject (SolarWinds-style
              decisive action: kick out the compromised supplier);
          (2) revoke trust: disable captured planes' directing relations, so a
              compromised controller can no longer direct its members;
          (3) reconfigure: cut compromised->clean estate bridges.
        Block (reference blacklisting) and clean (node state) remain tactical."""
        # (1) cut the source entirely and permanently
        if self.source is not None:
            for rc in RelationClass:
                for j in list(self.adj[rc].get(self.source, ())):
                    self._disable_relation(rc, int(self.source), int(j))
                    self.severed.add((rc, int(self.source), int(j)))
        # (2) revoke trust on captured directing planes
        self._revoke_trust(tick)
        # (3) reconfigure estate bridges
        self._reconfigure(tick)

    # ---- blind-lever experiment -------------------------------------------
    def _estate_undirected_adj(self):
        """Undirected estate CONNECTION adjacency (live edges only), excluding
        master and source. Built from self.adj, so it reflects the current graph
        after any earlier cuts. Used by the blind lever and bridge finder."""
        exclude = {x for x in (self.master, self.source) if x is not None}
        g = {}
        for i, nbrs in self.adj[RelationClass.CONNECTION].items():
            if i in exclude or not self.est[i]:
                continue
            for j in nbrs:
                if j in exclude or not self.est[j]:
                    continue
                g.setdefault(int(i), set()).add(int(j))
                g.setdefault(int(j), set()).add(int(i))
        return g

    def _bridge_edges(self):
        """Bridges (edges whose removal disconnects the graph) of the undirected
        estate CONNECTION graph, by a standard DFS. These are the sole-path edges,
        the structural 'cuts' the blind lever prioritises. Uses only the graph."""
        g = self._estate_undirected_adj()
        disc, low, parent = {}, {}, {}
        bridges = []
        timer = [0]
        import sys as _sys
        _sys.setrecursionlimit(10000)

        def dfs(u):
            disc[u] = low[u] = timer[0]; timer[0] += 1
            for v in g.get(u, ()):
                if v not in disc:
                    parent[v] = u
                    dfs(v)
                    low[u] = min(low[u], low[v])
                    if low[v] > disc[u]:
                        bridges.append((u, v))
                elif v != parent.get(u):
                    low[u] = min(low[u], disc[v])

        for s in list(g.keys()):
            if s not in disc:
                dfs(s)
        return bridges

    def _fanout(self, i: int) -> int:
        """Structural fan-out of node i: live out-degree on connection and
        directing-plane relations. Graph property only, no compromise state."""
        tot = 0
        for rc in (RelationClass.CONNECTION, RelationClass.CONTROL_PLANE_DIRECTING):
            tot += len(self.adj[rc].get(i, ()))
        return tot

    def _cut_edges(self, pairs, k: int):
        """Cut up to k distinct estate edges (CONNECTION where present), permanently.
        pairs is an ordered list of (i, j); de-duplicated; returns the number cut."""
        done = 0
        seen = set()
        for (i, j) in pairs:
            if done >= k:
                break
            key = (min(i, j), max(i, j))
            if key in seen:
                continue
            seen.add(key)
            rc = RelationClass.CONNECTION
            if j in self.adj[rc].get(i, ()) or i in self.adj[rc].get(j, ()):
                self._disable_relation(rc, i, j)
                self._disable_relation(rc, j, i)
                self.severed.add((rc, i, j))
                done += 1
        return done

    def _structural_blind(self, tick: int, k: int):
        """Visibility-free structural lever: cut k estate edges chosen by graph
        structure ALONE (never the compromise state). Sole-path (bridge) edges
        first, then highest supplying-node fan-out; ties by lowest indices."""
        cand = []
        for (u, v) in self._bridge_edges():                       # sole-path edges first
            cand.append((0, -(self._fanout(u) + self._fanout(v)), min(u, v), max(u, v)))
        g = self._estate_undirected_adj()                          # then by fan-out
        for u, nbrs in g.items():
            for v in nbrs:
                cand.append((1, -(self._fanout(u) + self._fanout(v)), min(u, v), max(u, v)))
        cand.sort()
        pairs = [(a, b) for _p, _f, a, b in cand]
        self._cut_edges(pairs, k)

    def _structural_informed(self, tick: int, k: int):
        """Matched informed control: cut up to k observed compromised-to-clean
        estate edges, highest supplying-node fan-out first, same tie-break. Uses
        the compromise state (what the blind lever is denied)."""
        comp = self._compromised_mask()
        cand = []
        rc = RelationClass.CONNECTION
        for i in np.flatnonzero(comp).tolist():
            if not self.est[i]:
                continue
            for j in self.adj[rc].get(i, ()):
                if self.state[j] != COMPROMISED and not self.isolated[j] and self.est[j]:
                    cand.append((-(self._fanout(int(i)) + self._fanout(int(j))),
                                 min(int(i), int(j)), max(int(i), int(j))))
        cand.sort()
        pairs = [(a, b) for _f, a, b in cand]
        self._cut_edges(pairs, k)

    def _apply_pending_blocks(self, tick: int):
        """The master pushes the fix (blacklist entry) along its plane to the
        estate. It takes hold on each node only with the defender success
        probability (degraded by drift), so the fix propagates stochastically
        rather than landing everywhere at once. A node that misses it this time
        gets another chance while the block stays pending-complete."""
        still = []
        for (t, ref) in self.pending_blocks:
            if t > tick:
                still.append((t, ref))
                continue
            missed = False
            for j in range(self.n):
                if ref in self.blacklist[j]:
                    continue
                if self._success():
                    self.blacklist[j].add(ref)
                else:
                    missed = True
            if missed:
                still.append((tick + 1, ref))   # keep pushing until it lands everywhere
        self.pending_blocks = still

    # ---- attacker actions -------------------------------------------------
    def _attacker(self, tick: int):
        comp = self._compromised_mask()
        budget = self.cfg.atk_budget
        # capture: once the master is compromised the attacker owns its push channel
        if self.master is not None and not self.attacker_owns_master \
                and self.state[self.master] == COMPROMISED:
            self.attacker_owns_master = True
        # 1. re-establish persistence on nodes the defender reset last tick that a
        #    compromised controller still governs (counters recovery)
        for j in list(self.last_reset):
            if budget <= 0:
                break
            if self.state[j] != COMPROMISED and not self.isolated[j]:
                if any(self.state[c] == COMPROMISED for c in self.controllers_of.get(j, ())):
                    self.state[j] = COMPROMISED
                    self.comp_ref[j] = self.atk_reference
                    budget -= 1
        # 2. re-enable relations the attacker controls (supplier compromised) that
        #    the defender cut, to reopen a route to a clean node
        if budget > 0:
            for rc in RelationClass:
                orig = self.net.access[rc]
                for i in np.flatnonzero(comp).tolist():
                    if budget <= 0:
                        break
                    if i == self.source:
                        continue
                    row_now = self.rel_enabled[rc][i]
                    # a relation present in the frozen network but currently disabled
                    cut = np.flatnonzero(orig[i] & ~row_now)
                    for j in cut.tolist():
                        if budget <= 0:
                            break
                        if (rc, i, int(j)) in self.severed:
                            continue   # defensive segmentation is permanent
                        if self.state[j] != COMPROMISED and not self.isolated[j]:
                            self.rel_enabled[rc][i, j] = True
                            self.adj[rc].setdefault(i, set()).add(j)
                            budget -= 1
        # 3. re-tool if the current campaign reference is broadly blacklisted
        if comp.any() and all(self.atk_reference in self.blacklist[j]
                              for j in np.flatnonzero(comp)):
            self.atk_reference = self._next_ref
            self._next_ref += 1
            self.first_seen_ref.setdefault(self.atk_reference, tick)
            self.comp_ref[self._compromised_mask()] = self.atk_reference

    # ---- main loop --------------------------------------------------------
    def seed_entry(self, node: str, reference: int = 0):
        j = self.net.index[node]
        self.state[j] = COMPROMISED
        self.comp_ref[j] = reference
        self.atk_reference = reference
        self.first_seen_ref[reference] = 0

    def run(self) -> Record:
        cfg = self.cfg
        for tick in range(1, cfg.horizon + 1):
            # 0 epistemic drift: delta grows with the compromised share, degrading
            #   the defender's success probability (control degradation; observation
            #   stays perfect in 4B). Mirrors the frozen core's eta = eta_0 e^{-alpha delta}.
            if cfg.drift_rate > 0:
                x = (self._compromised_mask() & self.est).sum() / max(int(self.est.sum()), 1)
                self.delta += cfg.drift_rate * x
            # 1 propagation
            self._deliver(tick)
            self._advance_residents(tick)
            self._master_push(tick)
            # 2 blocks that come due
            self._apply_pending_blocks(tick)
            # 3 defender: strategic (block / revoke / cut) before tactical clean,
            # so revoke sees a compromise before cleaning removes it this tick
            self._note_observed()
            if cfg.strategic_reconfigure:
                # austere 4B: block (fleet-wide reference blacklist) is TACTICAL
                # and runs on the fast tactical cadence regardless of adaptation.
                # Structural adaptation (reconfigure/revoke/cut-source) is the
                # slow lane, fires on the strategic cadence only when adaptation
                # is ON. OFF is the fixed-posture baseline (clean + block, no
                # structural change).
                block_cycle = cfg.block_cycle or cfg.tactical_cycle
                if cfg.defender_tactical and tick % block_cycle == 0:
                    self._block(tick)
                # structural action on the strategic cadence. blind_mode selects a
                # variant for the visibility-free experiment; otherwise the normal
                # adaptation path runs when adaptation is on.
                if cfg.blind_mode:
                    if tick % cfg.strategic_cycle == 0:
                        if cfg.blind_mode == "blind":
                            self._structural_blind(tick, cfg.blind_k)
                        elif cfg.blind_mode == "informed":
                            self._structural_informed(tick, cfg.blind_k)
                        # "none": no structural action
                elif cfg.adaptation and tick % cfg.strategic_cycle == 0:
                    self._strategic_adapt(tick)
            elif cfg.defender_strategic and tick % cfg.strategic_cycle == 0:
                self._strategic(tick)
            if cfg.defender_tactical and tick % cfg.tactical_cycle == 0:
                self._tactical(tick)
            # 4 attacker
            if cfg.attacker_on and tick % cfg.attacker_cycle == 0:
                self._attacker(tick)
            # 5 record
            self._record(tick)
        return self.rec

    def _record(self, tick: int):
        comp = int((self._compromised_mask() & self.est).sum())
        self.rec.tick.append(tick)
        self.rec.compromised.append(comp)
        self.rec.in_progress.append(len(self.resident))
        self.rec.isolated.append(int(self.isolated.sum()))
        self.rec.master_held_by_attacker.append(int(self.attacker_owns_master))
        self.rec.n_blacklisted.append(len(self.blacklist[0]))
        self.rec.n_references_live.append(len({int(r) for r in self.comp_ref if r >= 0}))


# ---------------------------------------------------------------------------
# Structure builders (representative family + management super node)
# ---------------------------------------------------------------------------

def _gov():
    return [Governance("estate", True), Governance("vendor", False)]


def _node(nid, gov="estate", I=True, X=True, A=True, visible=True):
    return Node(id=nid, governance=gov, interface=bool(I),
                execution_pathway=bool(X), authority=bool(A), visible=visible)


def _rates():
    return RateSpec(threat_capability=1.0, authority_rate=0.9, execution_rate=0.9,
                    control_variance=0.0)


def _admins_to_master(rels, estate_ids, seed):
    """Give the management master an inbound CONNECTION from a seeded ~5% of
    estate nodes (its administrators), excluding the entry node n0. This makes
    the master reachable only after the attack propagates to an admin, so the
    time to capture the master is structure-dependent (fast in mesh, deep in a
    chain, via the hub in a star). Connection is symmetric, so a compromised
    admin can pivot up this edge and compromise the master; the master's mgmt
    plane then falls to the attacker and pushes to the whole estate."""
    rng = np.random.default_rng(seed + 777)
    pool = [e for e in estate_ids if e != "n0"]
    k = max(2, int(round(0.05 * len(estate_ids))))
    admins = list(rng.choice(pool, min(k, len(pool)), replace=False)) if pool else []
    for a in admins:
        rels.append(Relation(a, "master", Condition.INTERFACE, RelationClass.CONNECTION))
    return admins


def build_chain(n_estate: int, with_master: bool, source: bool, seed: int):
    nodes = [_node(f"n{k}") for k in range(n_estate)]
    rels = []
    for k in range(n_estate - 1):
        rels.append(Relation(f"n{k}", f"n{k+1}", Condition.INTERFACE, RelationClass.CONNECTION))
    src = None
    if source:
        nodes.append(Node(id="src", governance="vendor", interface=True,
                          execution_pathway=True, authority=True, visible=False))
        rels.append(Relation("src", "n0", Condition.INTERFACE, RelationClass.CONNECTION))
        src = "src"
    master = None
    if with_master:
        nodes.append(_node("master", visible=True))
        for k in range(n_estate):
            rels.append(Relation("master", f"n{k}", Condition.AUTHORITY,
                                 RelationClass.CONTROL_PLANE_DIRECTING,
                                 conferral=True, group="mgmt"))
        _admins_to_master(rels, [f"n{k}" for k in range(n_estate)], seed)
        master = "master"
    spec = ScenarioSpec(id="chain", description="4B chain", governance=_gov(),
                        nodes=nodes, relations=rels, seed=seed, deterministic=False)
    return spec, master, src


def build_star(n_estate: int, with_master: bool, source: bool, seed: int):
    # hub plus leaves; hub is a directing control plane over leaves
    nodes = [_node("hub")] + [_node(f"n{k}") for k in range(n_estate - 1)]
    rels = []
    for k in range(n_estate - 1):
        # hub directs each leaf (push): compromise of the hub pushes to all leaves
        rels.append(Relation("hub", f"n{k}", Condition.AUTHORITY,
                             RelationClass.CONTROL_PLANE_DIRECTING, conferral=True, group="hub"))
        # each leaf also has an inbound CONNECTION to the hub (pull architecture:
        # agents connect in to the management server). Connection is symmetric,
        # so a compromised leaf can pivot up this edge and compromise the hub,
        # after which the hub's directing plane falls to the attacker and pushes
        # to every leaf -- the star's fragility (the CrowdStrike path).
        rels.append(Relation(f"n{k}", "hub", Condition.INTERFACE, RelationClass.CONNECTION))
    src = None
    if source:
        nodes.append(Node(id="src", governance="vendor", interface=True,
                          execution_pathway=True, authority=True, visible=False))
        rels.append(Relation("src", "n0", Condition.INTERFACE, RelationClass.CONNECTION))
        src = "src"
    master = None
    if with_master:
        nodes.append(_node("master", visible=True))
        est_ids = ["hub"] + [f"n{k}" for k in range(n_estate - 1)]
        for nd in est_ids:
            rels.append(Relation("master", nd, Condition.AUTHORITY,
                                 RelationClass.CONTROL_PLANE_DIRECTING, conferral=True, group="mgmt"))
        _admins_to_master(rels, est_ids, seed)
        master = "master"
    spec = ScenarioSpec(id="star", description="4B star", governance=_gov(),
                        nodes=nodes, relations=rels, seed=seed, deterministic=False)
    return spec, master, src


def build_mesh(n_estate: int, degree: int, with_master: bool, source: bool, seed: int):
    rng = np.random.default_rng(seed)
    nodes = [_node(f"n{k}") for k in range(n_estate)]
    rels = []
    seen = set()
    for a in range(n_estate):
        for _ in range(degree // 2):
            b = int(rng.integers(0, n_estate))
            if b == a or (a, b) in seen or (b, a) in seen:
                continue
            seen.add((a, b))
            rels.append(Relation(f"n{a}", f"n{b}", Condition.INTERFACE, RelationClass.CONNECTION))
    src = None
    if source:
        nodes.append(Node(id="src", governance="vendor", interface=True,
                          execution_pathway=True, authority=True, visible=False))
        rels.append(Relation("src", "n0", Condition.INTERFACE, RelationClass.CONNECTION))
        src = "src"
    master = None
    if with_master:
        nodes.append(_node("master", visible=True))
        for k in range(n_estate):
            rels.append(Relation("master", f"n{k}", Condition.AUTHORITY,
                                 RelationClass.CONTROL_PLANE_DIRECTING, conferral=True, group="mgmt"))
        _admins_to_master(rels, [f"n{k}" for k in range(n_estate)], seed)
        master = "master"
    spec = ScenarioSpec(id="mesh", description="4B mesh", governance=_gov(),
                        nodes=nodes, relations=rels, seed=seed, deterministic=False)
    return spec, master, src




# ############################################################################
#
#   PAPER 4C
#
#   Everything above this line is lifted verbatim: the frozen cemt_core v0.8
#   and the PhDPaper4B v0.23 engine and estate builders. Everything below is
#   new for Paper 4C.
#
# ############################################################################

from cemt_core.network import _beta_with_mean  # type: ignore # noqa: E402

DIRECTING = RelationClass.CONTROL_PLANE_DIRECTING
CONFERRING = RelationClass.CONTROL_PLANE_CONFERRING
CONNECTION = RelationClass.CONNECTION
CHANNEL = RelationClass.CHANNEL

# ---------------------------------------------------------------------------
# E8 settings, copied from PhDPaper4B v0.23 (DESIGN, TWO_CADENCE, CUSPMAP).
# They define what "spread" and "recovery" mean and what Gate 0 must reproduce.
#   spread   = attacker cadence (ticks between attacker actions; small = fast)
#   recovery = operational block cadence (ticks between fleet blocks; small = fast)
# ---------------------------------------------------------------------------
E8 = dict(
    spread=[2, 4, 8, 16, 32, 64],
    recovery=[2, 4, 8, 16, 32, 64],
    tau=0.30, lo_max=0.40, hi_min=0.60,
    seeds=[4101, 4201, 4202, 4301], R=10, horizon=600, n_estate=40,
    mesh_degree=6, strat_cycle=20,
    tac_budget=5, reconf_budget=30, atk_budget=1, def_success_prob=0.8,
    # Paper 4B Table IV: spread rows (of 6) that carry a bistable recovery window
    expected_bistable_rows={"chain": 6, "mesh": 6, "star": 0},
)
REFERENCE_ESTATE = 40   # the 4B estate size the defender budgets were set for
CAP_REF = 20.0          # Attacker Capability at which a node admits a payload at the 4B rate


def build_4b(structure: str, n_estate: int, seed: int):
    """The Paper 4B estate, exactly as PhDPaper4B v0.23 builds it."""
    if structure == "chain":
        return build_chain(n_estate, with_master=True, source=True, seed=seed)
    if structure == "star":
        return build_star(n_estate, with_master=True, source=True, seed=seed)
    return build_mesh(n_estate, E8["mesh_degree"], with_master=True, source=True, seed=seed)


def cfg_e8(atk_cyc: int, block_cyc: int, strat_cyc: int, horizon: int, seed: int,
           adaptation: bool) -> Config:
    """The E8 run configuration (PhDPaper4B v0.23 _cfg_cuspmap, unchanged):
    ungated recovery so the collapsed state is not absorbing, tactical clean
    fixed fast at 5, no drift."""
    return Config(
        horizon=horizon, obs_interval=5, tactical_cycle=5,
        strategic_cycle=strat_cyc, attacker_cycle=atk_cyc, block_delay=2,
        def_tactical_budget=E8["tac_budget"],
        def_strategic_budget=E8["reconf_budget"],
        atk_budget=E8["atk_budget"],
        defender_tactical=True, defender_strategic=False,
        strategic_revoke=False, attacker_on=True, gated_recovery=False,
        strategic_reconfigure=True, adaptation=adaptation, block_cycle=block_cyc,
        def_success_prob=E8["def_success_prob"], drift_alpha=0.0,
        drift_rate=0.0, seed=seed,
    )


# ---------------------------------------------------------------------------
# Network reuse. Engine4B.__init__ calls build_network(spec, rng) on every run,
# which rebuilds the relation table. For a fixed wiring only the per-node gate
# probabilities depend on the run seed, so the table is built once per
# configuration and the gate draws are repeated per run with the same generator
# calls the core makes. The wrapper below is consulted by Engine4B.__init__;
# with no override set it is the core function, unchanged.
# ---------------------------------------------------------------------------
_core_build_network = build_network
_NET_OVERRIDE: Optional[NetworkState] = None


def build_network(spec, rng):   # noqa: F811  (deliberately shadows the import)
    if _NET_OVERRIDE is not None:
        return _NET_OVERRIDE
    return _core_build_network(spec, rng)


def net_for_seed(template: NetworkState, seed: int) -> NetworkState:
    """The network build_network(spec, default_rng(seed)) would return, given a
    template built from the same spec: identical structure, gate probabilities
    drawn in the core's order (Execution, then Authority)."""
    spec = template.spec
    if spec.deterministic:
        return template
    rng = np.random.default_rng(seed)
    x = _beta_with_mean(spec.rates.execution_rate, spec.rates.control_variance, template.N, rng)
    a = _beta_with_mean(spec.rates.authority_rate, spec.rates.control_variance, template.N, rng)
    return dataclasses.replace(template, x_prob=x, a_prob=a)


# ============================================================================
# Engine4C
# ============================================================================
THETA_LEVELS = ("any", "majority", "all")
# theta acts on the directed supply classes. Connections are excluded: their
# arrangement is the topology itself, and a threshold on them would turn the
# backbone into a different contagion model.
THETA_CLASSES = (CHANNEL, DIRECTING)


@dataclass
class Domain:
    """One defender: the nodes it observes and may reset, its masters, budgets
    and cadences."""
    name: str
    mask: np.ndarray
    masters: List[int]
    tac_budget: int
    strat_budget: int
    block_cycle: int
    tactical_cycle: int
    strategic_cycle: int


@dataclass
class Opts:
    """Paper 4C settings on top of the 4B Config. Every default reproduces the
    4B engine exactly; each field is one knob of the register.

    theta            dependency threshold (any | majority | all)
    ext_clock        the other systems' defenders' cadences relative to the defender's
    dose             share of the relations into its own nodes a defender may cut
                     or revoke per structural turn. None = the 4B budget (30 per
                     40 nodes); 0 = no structural adaptation
    tac_per_40       tactical clean-ups per turn per 40 nodes defended (4B: 5)
    retool           ticks between new attack references from the persistent
                     source. None = the structural tempo, as in 4B, where the two
                     are one clock
    capability       attacker capability: multiplies a node's admission probability
    obs_interval     the defender refreshes its picture every this many ticks
                     (1 = every tick, which is what the 4B engine does)
    detect_latency   ticks before a newly compromised node can be observed
                     (0 = at once, which is what the 4B engine does)
    cap_drift        security drift: the attacker's capability rises by this
                     fraction per 100 ticks (0 = constant, as in 4B)
    blind_delay      ticks before a compromise on a node the defender cannot see
                     is found anyway, through its effects (9999 = never, which is
                     what the 4B engine does with an invisible node)

    Two-track recovery (all off = the 4B engine, where a block only prevents and
    a clean-up resets a node in place, most connected first):
    auto_clean       automated track: a block that lands on a node compromised
                     with that reference also cleans it, and each block turn the
                     plane re-cleans covered nodes holding a blocked reference.
                     Needs a clean master and reaches covered nodes only
    rebuild_time     manual track: a picked node is isolated at once and returns
                     clean after this many ticks; each team slot is busy until
                     then. 0 = reset in place
    priority         manual track picks the management masters first, then other
                     control-plane nodes, then Channel suppliers, then by
                     connections (4B: by connections only)
    manual_scope     the team works only on what automation cannot currently fix:
                     nodes without the control, nodes whose masters are all
                     captured, and the masters themselves (4B: any visible node)

    Relative capability (cap_rule "fixed" = the 4B engine: every defender action
    succeeds with the fixed probability in Config):
    atk_cap          Attacker Capability, 1 to 100. Also scales how readily a
                     reached node admits the payload (CAP_REF gives the 4B rate).
                     Security drift raises it through a run
    def_cap          Defence Capability, 1 to 100
    cap_rule         how the two set the chance that a defender action works:
                     "ratio"  Defence / (Defence + Attack), the ratio-form contest
                              success function (Tullock; Skaperdas 1996). No free
                              constant; depends only on relative capability
                     "cutoff" the fixed probability while Attack <= Defence,
                              nothing once the attacker is ahead

    Master capture (master_rebuild -1 = the 4B engine and v0.5: a captured master
    is handled like any other node and counts for the attacker only from the
    attacker's next action):
    master_rebuild   ticks to rebuild a captured management master from outside
                     the plane. A captured master cannot be reset or isolated: the
                     defender cannot log in to it. The capture takes effect on the
                     tick it happens; the attacker holds the plane, and pushes down
                     it, until the rebuild completes. The rebuild occupies one team
                     slot. A value at or beyond the horizon means the master is
                     never rebuilt (and no slot is spent on it)
    master_kills_sigs  while every master of a system is held, the automated
                     defence of that system is at zero: signatures already on its
                     nodes are lost, pending blocks are dropped, and (as before)
                     no new block or automated clean-up is issued. Acts only with
                     master_rebuild >= 0
    manual_delay     manual response delay: a node must have been in the
                     defender's picture for this many ticks before the team can
                     act on it (isolate it, or start a master rebuild). The
                     automated track is not affected. 0 = at once
    lockout_delay    (estates built with plane roles only) while the identity plane
                     of a system is held, the team's response delay in that system
                     is this many ticks if longer than manual_delay; at or beyond
                     the horizon the team is locked out of that system. Master
                     rebuilds are done from outside the plane and are not affected
    Structure and the flag (v0.9; all off = the 4B engine):
    flag             the game is over, and the run stops, when this share of the
                     estate is compromised (0 = no flag)
    reconf_time      ticks from the capture of a master controller to its push
                     reconfiguring the nodes it reaches
    ctl_link         which controllers of the same kind are in communication
                     (0 none, 1 neighbouring zones, 2 all)
    repl_delay       ticks for a captured controller's authority to reach a
                     linked controller (-1 = no link)
    stage_time       staged rollout: a delivery channel reaches its nodes in a
                     fixed order spread over this many ticks. It binds an
                     attacker that holds only the channel, not one that holds
                     the zone's Active Directory or DNS, and never the defender
    hand_delay       ticks after a signature lands before it reaches a control
                     that endpoint detection does not manage

    The payload (v0.9): infected is not captured
    payload          a payload that completes its arrival leaves the node
                     infected: silent, unseen, and infecting its neighbours over
                     Connections. When its delay expires it triggers, and the
                     node's control answers: the node is captured with chance
                     Attack / (Attack + Defence), otherwise the payload is
                     repelled, the node is clean, and the defender has seen the
                     attack and blocks it
    payload_delay    the usual delay before a payload triggers
    dormant_share    share of attacks whose payload carries the long timer
    dormant_delay    the long timer
    cap_spread       each attack's capability is the Attacker Capability times
                     a factor drawn evenly from 1 - spread to 1 + spread

    kind             the attack kind (None or "mixed" = every behaviour at once):
                     malware | implant | intrusion | stealer. See KINDS
    fixed_clock      share of dormant attacks whose payloads trigger together on
                     one fixed tick (the tick the attack started plus its delay)
                     instead of each node's arrival plus the delay

    ext_bad          chance that each external party is compromised at the start of
                     the run (1 = always, as before v0.11)
    edr_site         1 = endpoint detection is run by a third party. With the
                     chance ext_bad that vendor is compromised at the start of
                     the run, and every console with it. The defender cannot
                     restore a third party's service
    dns_site         1 = DNS is run by a third party, compromised at the start
                     with the same chance, and not the defender's to restore

    The ceiling on a Channel (v0.13; -1 = no ceiling, as before)
    ceil_deliv, ceil_edr, ceil_ext
                     the maximum authority a software-delivery Channel, the
                     endpoint detection Channel and an external supplier's
                     Channel can deliver (1 to 100). A Connection's is 0 and a
                     Control Plane's is 100. A payload arriving on a Channel is
                     guaranteed to run; it acts with no more than the ceiling
                     and does not reconfigure the node. If its rating is above
                     the ceiling and the node carries a control it alarms, and
                     if the node is visible the defender resolves it by hand
    route_cred, route_sup, route_lat
                     switches for the route-ablation pilot: the credential
                     route to a Control Plane, the supplier route (external
                     parties and third-party services), and the lateral route
                     (node to node spread and hands-on moves)

    Stages, mapped to ATT&CK tactics (v0.14; stages = False gives v0.13)
    stages           every action needs a level of Authority. A payload that
                     arrived over a Connection had to win the node's own checks
                     and holds the node's Authority (100). One delivered by a
                     Channel holds the Channel's ceiling: anything at or below
                     it is done silently; anything above it is a Privilege
                     Escalation attempt, contested against Defender Capability
                     and raising an alarm where the node has a live control. A
                     won attempt gives the node's Authority. The ceiling no
                     longer weakens the payload in the trigger contest
    auth_cred, auth_destroy, auth_reconf
                     the Authority needed for Credential Access, to take a
                     node out of service (Impact), and to reconfigure it
    route_esc        switch: Privilege Escalation attempts are made
    c2               Command and Control: a hands-on operator, Credential
                     Access and Exfiltration work only on a held node that can
                     call out, itself or through held neighbours (layout
                     "egress" lists the nodes with a route out)
    objective        what the payload is for: steal | destroy | both, or
                     "kind" for the default of the attack kind
    exfil_p          chance an Exfiltration attempt succeeds (one attempt per
                     node held); data value is lost only where it does
    val_sv, dval_sv, dval_exc
                     node value of a server, data value of a server and of an
                     exceptional endpoint, each relative to an ordinary
                     endpoint (1). Node value is revenue per tick, lost while
                     the node is out of service; data value is lost once
    flag_value       the second flag: the game is over when this share of
                     the estate's node value has been taken out by the attack
    queue            the team is one queue of work: investigating an alarm
                     (manual_delay), cleaning a node (t_clean), rebuilding one
                     (rebuild_time) and cutting a relation (t_cut) are jobs
                     with a duration, done by tac_budget responders in the
                     order queue_order (value | fifo | degree)

    The three stages of a held node (v0.17, Paul's ruling of 18 October)
      1 Compromised: a foothold. Reclaimable in place. A stealing payload
        makes one Exfiltration attempt against the control that protects
        data (chance exfil_p); if that control holds it keeps holding
      2 Escalated: Privilege Escalation contested by Defender Capability
        (the EDR) where the node has a live agent, and alarmed. On a win the
        node is at once unreclaimable in place and out of service: revenue
        stops until the team isolates and rebuilds it. Credential Access is
        available from here. A second Exfiltration attempt is made, against
        the network control only (chance exfil_esc)
      3 Reconfigured: after node_reconf ticks at stage 2 the node is a
        supplier to its neighbours and its own agent is disabled
    auth_conn        the Authority a payload holds after winning a node's own
                     checks over a Connection. Rule (18 October): 0, a
                     foothold; 100 was the v0.14 default and is kept as a
                     sensitivity switch
    retry            the footholds belong to the attacker, not the payload: each
                     new payload the source issues (every retool ticks, with its
                     own signature and capability) also executes on every
                     foothold the attacker still holds and makes a fresh
                     escalation attempt there, contested and alarmed as always
    hunt             hunt on alarm: when the team's investigation of an alarmed
                     node completes, it queues work for every node with an
                     agent that holds the same payload (stage 1 cleaned, stage 2
                     rebuilt). The hunt interrogates agents, so Control Presence
                     bounds it; the alarm needs a listener, so Visibility bounds
                     that. A node with no agent is reached by neither
    sig_block        a control blocks in two ways that add (Paul, 18 October):
                     an unknown payload by Defender Capability as a probability
                     (the contest), and a known signature by matching, at this
                     reliability (99 per cent). The known signature reaches
                     every agent. A payload that slips the match still faces the
                     contest. -1 = v0.17 (a known signature blocks with certainty,
                     but reaches each agent only by the capability contest)
    exfil_esc        chance an Exfiltration attempt succeeds after escalation
    stage_down       rule: a won escalation takes the node out of service
                     (False = v0.16: only a destructive payload did)
    down_inert       True = a node taken out of service cannot be used by the
                     attacker to move, deliver or take a credential (rule: it can)
    master_rebuild   with the queue: ticks for the team to rebuild a captured
                     Control Plane (rule: never, 9999)

    Reconfigure (v0.9)
    node_reconf      ticks a node must stay captured before the attacker has
                     reconfigured it (-1 = never). A reconfigured node attacks its
                     neighbours as a supplier (its Connections also supply the
                     Execution Pathway), cannot be cleaned by the automated track
                     (it needs a manual rebuild), and counts toward impact
    retool_fix       the attacker re-tools once its current reference is blocked
                     on every node it holds that carries the control (nodes
                     without the control can never be blocked, and no longer veto
                     the re-tool); holding none, once it is blocked on more than
                     half of the nodes that carry the control. False = the 4B rule
    """
    theta: str = "any"
    ext_clock: float = 1.0
    dose: Optional[float] = None
    tac_per_40: Optional[float] = None
    retool: Optional[int] = None
    capability: float = 1.0
    obs_interval: int = 1
    detect_latency: int = 0
    cap_drift: float = 0.0
    blind_delay: int = 9999
    auto_clean: bool = False
    rebuild_time: int = 0
    priority: bool = False
    manual_scope: bool = False
    cap_rule: str = "fixed"
    atk_cap: Optional[float] = None
    def_cap: float = 80.0
    master_rebuild: int = -1
    master_kills_sigs: bool = True
    manual_delay: int = 0
    retool_fix: bool = False
    lockout_delay: int = 0
    flag: float = 0.0
    reconf_time: int = 0
    repl_delay: int = -1
    ctl_link: int = 0
    stage_time: int = 0
    hand_delay: int = 0
    payload: bool = False
    payload_delay: int = 1
    dormant_share: float = 0.0
    dormant_delay: int = 48
    cap_spread: float = 0.0
    node_reconf: int = -1
    kind: Optional[str] = None
    fixed_clock: float = 0.0
    ext_bad: float = 1.0
    cloud_bad: float = 0.0
    edr_site: int = 0
    dns_site: int = 0
    ceil_deliv: float = -1.0
    ceil_edr: float = -1.0
    ceil_ext: float = -1.0
    route_cred: bool = True
    route_sup: bool = True
    route_lat: bool = True
    # ---- v0.14: stages mapped to ATT&CK tactics. Authority per action, Command and Control,
    # objective and value, and the team's single work queue (all off = v0.13)
    stages: bool = False
    auth_cred: float = 70.0
    auth_destroy: float = 50.0
    auth_reconf: float = 100.0
    route_esc: bool = True
    c2: bool = False
    objective: str = "kind"
    exfil_p: float = 0.5
    val_sv: float = 10.0
    dval_sv: float = 20.0
    dval_exc: float = 10.0
    flag_value: float = 0.0
    queue: bool = False
    t_clean: int = 1
    t_cut: int = 1
    queue_order: str = "value"
    # ---- v0.15: sensitivity switches for the confirmatory study (defaults = v0.14)
    auth_conn: float = 0.0
    down_inert: bool = False
    # ---- v0.17 (Paul, 18 October): the three stages of a held node
    exfil_esc: float = 0.9
    stage_down: bool = True
    # ---- v0.18 (Paul, 18 October): the attacker's footholds, and the hunt
    retry: bool = True
    hunt: bool = True
    sig_block: float = 0.99
    # ---- v0.21 (Paul, 18 October): stolen service credentials, and the campaign
    steal_p: float = 0.5        # chance a stealer landing on a credential-holding node takes that service's credential
    rotate: int = 1             # 0 never; 1 a cleaned or rebuilt node's stolen credentials are rotated; 2 every
                                #   stolen credential of each service that node held is rotated
    cred_ttl: int = 9999        # ticks a stolen credential stays valid on its own (9999 = until rotated)
    handoff: int = 20           # campaign: ticks of stealer payloads before the intrusion payloads begin


def _scaled_budget(base: float, n_nodes: int) -> int:
    """Defender capacity per node is held at the 4B level (budget set for an
    estate of 40), so a larger estate is not weaker merely by dilution."""
    return max(1, int(np.floor(base * n_nodes / REFERENCE_ESTATE + 0.5)))


def _split(total: int, parts: int) -> List[int]:
    q, r = divmod(total, parts)
    return [max(1, q + (1 if i < r else 0)) for i in range(parts)]


# Common observation times for the damage measures (ticks, read as hours: one
# day, three days, one week). Lost and surviving runs are compared at these.
MARK_TICKS = (24, 72, 168)


class Engine4C(Engine4B):
    """The 4B engine generalised to K systems (clusters).

    layout = dict(clusters=[[node ids]...],
                  masters=[[master ids of cluster k]...],
                  source=hostile source id, gamma=0 or 1,
                  covered=[[ids the management plane reaches]...]   (optional)
                  closed=[ids whose interface is closed to connections] (optional))

    Reduction: with one cluster, one master and default Opts this class makes
    the same random draws in the same order as Engine4B and returns the same
    trajectory. Gate 0(a) verifies that run for run.
    """

    def __init__(self, spec: ScenarioSpec, cfg: Config, layout: dict,
                 net: Optional[NetworkState] = None, opts: Optional[Opts] = None):
        global _NET_OVERRIDE
        _NET_OVERRIDE = net
        try:
            super().__init__(spec, cfg, master=layout["masters"][0][0],
                             source=layout["source"], source_trusted=True)
        finally:
            _NET_OVERRIDE = None
        self.o = o = opts or Opts()
        if o.theta not in THETA_LEVELS:
            raise ValueError(f"theta must be one of {THETA_LEVELS}")
        self.theta = o.theta
        self.gamma = int(layout["gamma"])
        idx = self.net.index
        n = self.n
        self.masters_of: List[List[int]] = [[idx[m] for m in ms] for ms in layout["masters"]]
        self.masters: List[int] = [m for ms in self.masters_of for m in ms]
        self.K = len(self.masters_of)
        self.cluster_nodes = [np.array([idx[i] for i in c], dtype=int)
                              for c in layout["clusters"]]
        self.hostile = np.zeros(n, dtype=bool)
        self.hostile[self.source] = True
        for x_ in layout.get("ext_nodes", ()):
            self.hostile[idx[x_]] = True
        self.cluster_of = np.full(n, -1, dtype=int)
        for k in range(self.K):
            self.cluster_of[self.cluster_nodes[k]] = k
            for m in self.masters_of[k]:
                self.cluster_of[m] = k
        # services run by a third party are outside the estate: never in the
        # defender's masks, nor in any count of the estate
        for x_ in layout.get("outside", ()):
            self.hostile[idx[x_]] = True
            self.cluster_of[idx[x_]] = -1
        self.owned_masters: Set[int] = set()
        # a block is pushed along the management plane: it reaches the nodes the
        # plane covers, the masters, and (as in 4B, where the push covers every
        # node) the hostile source, on which it has no effect
        covered = layout.get("covered")
        self.push_scope = []
        for k in range(self.K):
            scope = (self.cluster_of == k) | self.hostile
            if covered is not None:
                cov = np.zeros(n, dtype=bool)
                cov[[idx[i] for i in covered[k]]] = True
                cov[self.masters_of[k]] = True
                scope = (scope & cov) | self.hostile
            self.push_scope.append(np.flatnonzero(scope))
        # Control Coverage: the nodes the management plane's control reaches
        self._covered = np.zeros(n, dtype=bool)
        for k in range(self.K):
            self._covered[self.push_scope[k]] = True
        self._covered &= ~self.hostile
        self._carries = self._covered.copy()       # nodes a signature can land on
        for i in layout.get("closed", ()):
            self.iface_removed[idx[i]] = True
        self._closed = self.iface_removed.tolist()
        self.home_mask = (self.cluster_of == 0) & ~self.hostile
        self.all_mask = (self.cluster_of >= 0) & ~self.hostile

        # ---- defenders ---------------------------------------------------
        n_nodes = int(sum(len(c) for c in self.cluster_nodes))
        tac_base = cfg.def_tactical_budget if o.tac_per_40 is None else o.tac_per_40
        tac = _scaled_budget(tac_base, n_nodes)
        bc = cfg.block_cycle or cfg.tactical_cycle
        if self.gamma == 0 or self.K == 1:
            masks = [self.all_mask.copy()]
            tacs = [tac]
            names = ["estate"]
            mlist = [list(self.masters)]
        else:
            masks = [self.cluster_of == k for k in range(self.K)]
            tacs = _split(tac, self.K)
            names = [f"g{k}" for k in range(self.K)]
            mlist = [list(self.masters_of[k]) for k in range(self.K)]
        if o.dose is None:
            total = _scaled_budget(cfg.def_strategic_budget, n_nodes)
            strats = [total] if len(masks) == 1 else _split(total, len(masks))
        else:
            strats = []
            for mk in masks:
                inbound = sum(int(self.rel_enabled[rc][:, mk].sum()) for rc in RelationClass)
                strats.append(max(1, int(round(o.dose * inbound))) if o.dose > 0 else 0)
        self.adapt_on = bool(cfg.adaptation) if o.dose is None else (o.dose > 0)
        self.domains: List[Domain] = []
        for d, mk in enumerate(masks):
            s = 1.0 if d == 0 else float(o.ext_clock)
            self.domains.append(Domain(
                names[d], mk, mlist[d], tacs[d], strats[d],
                max(1, int(round(bc * s))), max(1, int(round(cfg.tactical_cycle * s))),
                max(1, int(round(cfg.strategic_cycle * s)))))
        # the defender's own nodes: every cluster under one governance, cluster 0
        # when each is separately governed
        self.def_mask = self.all_mask if (self.gamma == 0 or self.K == 1) else self.home_mask
        self._def_idx = np.flatnonzero(self.def_mask)
        self._csize = np.array([float((self.cluster_of == k).sum()) for k in range(self.K)])

        # ---- supplier lists (static wiring) ------------------------------
        self._sup: Dict[RelationClass, Dict[int, List[int]]] = {}
        for rc in (CHANNEL, DIRECTING, CONFERRING):
            d_: Dict[int, List[int]] = {}
            rows, cols = np.nonzero(self.net.access[rc])
            for i_, j_ in zip(rows.tolist(), cols.tolist()):
                d_.setdefault(j_, []).append(i_)
            self._sup[rc] = d_
        self._flat_cache: Dict[int, list] = {}
        # ---- two-track recovery --------------------------------------------
        self._manual = o.rebuild_time > 0
        self._two_track = bool(o.auto_clean or self._manual or o.priority or o.manual_scope)
        self._rebuilding: List[List[tuple]] = [[] for _ in self.domains]
        # master capture rules and the manual response delay (off = v0.5 and 4B)
        self._mr_on = int(o.master_rebuild) >= 0
        self._mdelay = max(0, int(o.manual_delay))
        # plane roles (estates from the 4C generator): in each system the first
        # master is the endpoint protection plane, which alone carries the
        # automated defence; the second is the identity plane, whose capture
        # slows or locks out the manual team; any others are administrative
        # planes that defend nothing. Without roles (the 4B estate) every master
        # carries the defence, as before
        self._roles = bool(layout.get("roles", False))
        self._def_masters = [[int(ms[0])] if self._roles else [int(x) for x in ms]
                             for ms in self.masters_of]
        self._def_set = set(x for ms in self._def_masters for x in ms)
        self._id_master = [int(ms[1]) if (self._roles and len(ms) > 1) else -1
                           for ms in self.masters_of]
        self._lockout = max(0, int(o.lockout_delay)) if (self._roles and self._mr_on) else 0
        self._dns = idx[layout["dns"]] if layout.get("dns") else -1
        self._lock_live = self._lockout > self._mdelay and (
            any(x >= 0 for x in self._id_master) or bool(layout.get("estate_masters")))
        self._track_seen = bool(self._mdelay or self._lock_live or self._roles)
        # ---- structure of v0.9: credentials, controller links, delivery channels
        self._cred = {idx[m_]: [idx[i] for i in v] for m_, v in layout.get("cred", {}).items()}
        # masters over a whole kind of node (hypervisor, device management):
        # they belong to no group, are never cleaned, and their capture excludes
        # the defender from every group they hold authority over
        self._over: List[List[int]] = [[] for _ in range(self.K)]
        self._ext = [idx[x_] for x_ in layout.get("ext_nodes", ())]
        # services sited with a third party (DNS when dns_site = 1): outside
        # the estate, so the defender cannot see, isolate or restore them
        self._outside = [idx[x_] for x_ in layout.get("outside", ())]
        self._outside_draw = [idx[x_] for x_ in layout.get("outside_draw", layout.get("outside", ()))]
        self._outside_cloud = [idx[x_] for x_ in layout.get("outside_cloud", ())]
        # ---- Control Planes: who is excluded follows reach, node by node
        self._excl = np.zeros(n, dtype=bool)
        self._alarm = np.full(n, -1, dtype=int)
        self._inf_capv = np.full(n, -1.0)
        self._norec = np.zeros(n, dtype=bool)
        self.n_alarms = 0
        # replication links Active Directory controllers only
        self._kinds = [[int(ms[1]) for ms in self.masters_of if len(ms) > 1]] if self._roles else []
        self._channels = []
        for ch in layout.get("channels", ()):
            s_ = idx[ch["server"]]
            ceil = {"chan": (o.ceil_ext if ch["external"] else o.ceil_deliv), "ctl": 100.0}[ch["kind"]]
            self._channels.append(dict(server=s_, kind=ch["kind"], external=bool(ch["external"]),
                                       zone=int(self.cluster_of[s_]), ceil=float(ceil),
                                       verified=bool(ch.get("verified", False)),
                                       served=[(idx[j], float(fr)) for j, fr in ch["served"]]))
        self._hand = [[idx[i] for i in v] for v in layout.get("control_only", [[] for _ in range(self.K)])]
        self._has_control = self._covered.copy()
        for v in self._hand:
            self._has_control[v] = True
        self._carries = self._has_control.copy()
        self._hand_pending: List[tuple] = []
        self._hand_done: Set[tuple] = set()
        self._cap_tick: Dict[int, int] = {}
        self._ch_start: Dict[tuple, int] = {}
        self._ch_tried: Set[tuple] = set()
        self._known_refs: Set[int] = set()
        self._cause = np.zeros(n, dtype=np.int8)      # 1 connection (lateral), 2 channel, 3 controller, 4 entry
        self._flag = float(o.flag)
        self._reconf = max(0, int(o.reconf_time))
        self.t_flag = -1
        self._last_share = 0.0
        # ---- the payload: infected, then captured or repelled
        self._payload = bool(o.payload)
        self._inf_ref = np.full(n, -1, dtype=int)
        self._inf_due = np.zeros(n, dtype=int)
        self._ref_prop: Dict[int, tuple] = {}
        self._pay_rng = np.random.default_rng([int(cfg.seed) & 0x7FFFFFFF, 7701])
        self.n_infected = 0
        self.n_repelled = 0
        # ---- attack kind: which behaviours this run's attacks have
        k_ = o.kind if self._roles else None
        self._kind = k_
        self._harvest: Set[int] = set()
        # v0.21: the attacker's store of stolen service credentials: service -> {node it
        # was taken from: tick}. The campaign kind runs stealer payloads first and
        # intrusion payloads from the handoff tick; both phases draw on the store
        self._stolen: Dict[int, Dict[int, int]] = {}
        self._cred_rng = np.random.default_rng([int(cfg.seed) & 0x7FFFFFFF, 7702])
        self.n_stolen = 0
        self.n_spent = 0
        self._phase = "stealer" if k_ == "campaign" else k_
        # ---- reconfigure and impact
        self._nrec = int(o.node_reconf)
        self._rec = np.zeros(n, dtype=bool)
        self.impact = 0.0
        self._seen = np.full(n, -1, dtype=int)      # tick a compromise entered the picture
        self._master_set = set(int(x) for x in self.masters)
        self._cp_set: Set[int] = set()
        self._cp_rebuild = False
        self._marks: Dict[int, tuple] = {}
        if self._mr_on:
            self._two_track = True
        # manual priority: the management masters, then other control-plane nodes
        # (controllers of directing planes, issuers of conferred Authority), then
        # Channel suppliers, then everything else; by connections within a tier
        tier = np.full(n, 3, dtype=int)
        tier[list(self.adj[CHANNEL].keys())] = 2
        for _g, (ctl, _m) in self.net.control_planes.items():
            tier[int(ctl)] = 1
        for _g, (iss, _m) in self.net.conferring_planes.items():
            tier[int(iss)] = 1
        tier[self.masters] = 0
        if layout.get("dns"):
            tier[idx[layout["dns"]]] = 0
        self._tier = tier.tolist()
        self._has_rollout = bool(self.net.rollout_delays)

        # ---- observation and trajectory records --------------------------
        self._comp_tick = np.full(n, -1, dtype=int)
        # what the defender is told of: a node reports a compromise only if it
        # carries a control (which raises the alarm) and is visible (so the
        # alarm arrives). Service nodes (consoles, controllers, DNS) report
        # for themselves. On a 4B estate every visible node reports, as before
        if self._roles:
            ordinary = np.zeros(n, dtype=bool)
            for c_ in self.cluster_nodes:
                ordinary[c_] = True
            if self._dns >= 0:
                ordinary[self._dns] = False
            self._vis = self.net.visible & (self._has_control | ~ordinary)
            # the estate that is counted (the flag, shares, losses) is its
            # endpoints and servers; services are not nodes of the estate
            self._ord = ordinary
            self._def_idx = np.flatnonzero(ordinary)
        else:
            self._vis = self.net.visible
            self._ord = self.def_mask.copy()
        # ---- v0.14: stages, values, Command and Control, the work queue
        self._stages = bool(o.stages) and self._roles and self._payload
        self._cred_of: Dict[int, List[int]] = {}
        for m_, nodes in self._cred.items():
            for j_ in nodes:
                self._cred_of.setdefault(int(j_), []).append(int(m_))
        self._L = np.zeros(n)                       # Authority the attacker holds on a node
        self._down = np.zeros(n, dtype=bool)        # taken out of service by the attack
        self._exfil = np.zeros(n, dtype=bool)       # data has left
        self._tried_x = np.zeros(n, dtype=bool)     # exfiltration attempted on this hold
        self._rec3 = np.zeros(n, dtype=bool)        # stage 3: supplier to neighbours, agent disabled
        self._last_retry_ref = -1
        self.n_hunt = 0
        self._t2 = np.full(n, -1, dtype=int)        # tick the node reached stage 2
        self.n_esc = 0
        self.n_esc_won = 0
        self.svc_att = 0.0
        self.svc_def = 0.0
        self.which_flag = 0
        self._apply_kind(self._phase)
        self._nval = np.zeros(n)
        self._dval = np.zeros(n)
        types = layout.get("types") or []
        for k in range(self.K):
            server = k < len(types) and types[k] in ("sv", "cloud")
            c_ = self.cluster_nodes[k]
            self._nval[c_] = float(o.val_sv) if server else 1.0
            self._dval[c_] = float(o.dval_sv) if server else 1.0
        for x_ in layout.get("exceptional", ()):
            self._dval[idx[x_]] = float(o.dval_exc)
        self._nval[~self._ord] = 0.0
        self._dval[~self._ord] = 0.0
        self._nval_tot = max(float(self._nval.sum()), 1e-9)
        self._dval_tot = max(float(self._dval.sum()), 1e-9)
        # queue priority: a node's own value; a service, the value it serves
        self._pval = self._nval + 1e-3 * self._dval
        if self._roles:
            for ms in self._def_masters:
                for m_ in ms:
                    self._pval[m_] = float(self._nval[self.net.access[DIRECTING][m_]].sum()) + 1.0
            if self._dns >= 0:
                self._pval[self._dns] = self._nval_tot + 2.0
        self._svc_set = (set(x for ms in self._def_masters for x in ms)
                         | ({self._dns} if self._dns >= 0 else set())) if self._roles else set()
        self._c2 = bool(o.c2) and self._stages
        eg = layout.get("egress")
        self._egress = np.ones(n, dtype=bool)
        if eg is not None:
            self._egress[:] = False
            self._egress[[idx[x_] for x_ in eg]] = True
        self._contact = np.ones(n, dtype=bool)
        self._queue = bool(o.queue) and self._roles
        self._jobs: List[dict] = []
        self._job_keys: Set[tuple] = set()
        self._known = np.zeros(n, dtype=bool)
        self._evid: Set[int] = set()
        self._xexcl: List[int] = []
        self.q_max = 0
        self.q_wait = 0.0
        self.q_started = 0
        self._blind_live = bool(o.blind_delay < cfg.horizon and not self._vis[self.all_mask].all())
        self._track_age = o.detect_latency > 0 or self._blind_live or int(o.node_reconf) >= 0
        self._snap: List[Optional[np.ndarray]] = [None] * len(self.domains)
        self._tick = 0
        self.area = 0.0
        self.peak = 0.0
        self.t_major = -1
        self.t_cluster = np.full(self.K, -1, dtype=int)
        self.t_master = {m: -1 for m in self.masters}
        for mid in layout.get("estate_masters", ()):
            mi = idx[mid]
            self.masters.append(mi)
            self.t_master[mi] = -1
            self._master_set.add(mi)
            self._tier[mi] = 0
            for k in layout["authority"][mid]:
                self._over[k].append(mi)
        self._cp_set = set(self._control_planes())
        self._cp_rebuild = 0 <= int(o.master_rebuild) < int(cfg.horizon)

    # ---- corners: native, or supplied by a live relation --------------------
    def _live_supply(self, rc: RelationClass, j: int) -> bool:
        en = self.rel_enabled[rc]
        return any(en[i, j] for i in self._sup[rc].get(j, ()))

    def _has_X(self, j: int) -> bool:
        """Execution Pathway holds natively, or is supplied by a Channel that has
        not been cut. 4B's rule when every node holds the corner natively."""
        if self.exec_removed[j]:
            return False
        if self.net.x_present[j]:
            return True
        return self._live_supply(CHANNEL, j)

    def _has_A(self, j: int) -> bool:
        """Authority holds natively, or is conferred by a control plane whose
        relation has not been cut."""
        if self.authority_revoked[j]:
            return False
        if self.net.a_present[j]:
            return True
        return self._live_supply(CONFERRING, j)

    # ---- attacker capability -----------------------------------------------
    def _admit(self, j: int) -> bool:
        if self.deterministic:
            return True
        p = float(self.net.x_prob[j] * self.net.a_prob[j])
        if self.o.atk_cap is None:
            p *= self.o.capability
            if self.o.cap_drift:
                p *= 1.0 + self.o.cap_drift * self._tick / 100.0
        else:
            p *= self._attack_now() / CAP_REF
        return bool(self.rng.random() < min(max(p, 0.0), 1.0))

    def _attack_now(self) -> float:
        """Attacker Capability at this tick: its starting value, raised by
        security drift."""
        base = CAP_REF if self.o.atk_cap is None else float(self.o.atk_cap)
        return base * (1.0 + self.o.cap_drift * self._tick / 100.0)

    def _success(self) -> bool:
        """Does a defender action (a block landing, an automated clean, a manual
        rebuild) work? Under the 4B rule, with a fixed probability. Otherwise
        from the relative capability of the two sides."""
        rule = self.o.cap_rule
        if rule == "fixed" or self.o.atk_cap is None:
            return super()._success()
        A, D = self._attack_now(), float(self.o.def_cap)
        if rule == "ratio":
            p = D / (D + A)
        elif rule == "cutoff":
            p = self.cfg.def_success_prob if A <= D else 0.0
        else:
            raise ValueError(f"unknown cap_rule {rule!r}")
        if p >= 1.0:
            return True
        return bool(self._pol_rng.random() < max(0.0, p))

    def _auto_available(self, j: int) -> bool:
        """Can the automated track currently fix node j? It must carry the
        control, not be a master itself, and have a clean master to push from."""
        if not self.o.auto_clean or not self._covered[j] or not self._sig:
            return False                # nothing to match without a signature: the team must do it
        if self._roles and self._dns_held():
            return False                # the automated track cannot reach the node
        k = int(self.cluster_of[j])
        if k < 0 or j in self.t_master or self._rec[j] or self._down[j]:
            return False
        if self._excl[j]:
            return False
        return any(self.state[m] != COMPROMISED and not self.isolated[m]
                   for m in self._def_masters[k])

    def _apply_kind(self, k_):
        """The behaviours of the attack kind in play. Called once at the start,
        and again at the handoff of a campaign, when the stealer payloads give
        way to intrusion payloads (v0.21)."""
        o = self.o
        self._phase = k_
        every = k_ in (None, "mixed")
        self._k_iface = every or k_ in ("malware", "stealer", "intrusion")   # enters by Interface
        self._k_xchan = every or k_ == "implant"                             # enters by an external Channel
        self._k_xctl = every or k_ == "intrusion"                            # enters with outside Authority
        self._k_ichan = every or k_ in ("implant", "intrusion")              # can operate a captured channel
        self._k_spread = (every or k_ == "malware") and bool(o.route_lat)    # spreads to neighbours unaided
        self._k_moves = k_ in ("implant", "intrusion") and bool(o.route_lat) # moved by hand, a few steps a tick
        self._k_cred = (every or k_ in ("implant", "intrusion")) and bool(o.route_cred)   # can use a credential
        self._sig = k_ != "intrusion"                                        # leaves a signature
        obj = str(o.objective)
        if obj == "kind":
            obj = dict(malware="destroy", implant="steal", intrusion="both",
                       stealer="steal").get(k_, "both")
        self._steal = self._stages and obj in ("steal", "both")
        self._destroy = self._stages and obj in ("destroy", "both")
        # what the payload wants beyond its foothold: a credential, or (rule)
        # the node itself, since a won escalation takes it out of service
        self._want = max([0.0] + ([float(o.auth_cred)] if self._k_cred else [])
                         + ([float(o.auth_destroy)] if (self._destroy and not o.stage_down) else [])
                         + ([float(o.auth_cred)] if o.stage_down else []))

    # ---- v0.21: stolen service credentials -------------------------------------------
    def _steal_from(self, j: int, tick: int, by_stealer: bool):
        """Credential theft on node j. A stealer reads the service credentials
        the node's user holds as they are stored, with probability steal_p each
        and no Authority condition; a hands-on attacker at Credential Access
        takes them with certainty (it has the Authority to dump them). Either
        way the credential enters the attacker's store and outlives the hold."""
        for m_ in self._cred_of.get(j, ()):
            if by_stealer and not (self._cred_rng.random() < self.o.steal_p):
                continue
            rec = self._stolen.setdefault(m_, {})
            if j not in rec:
                self.n_stolen += 1
            rec[j] = tick

    def _spend_credentials(self, tick: int):
        """A payload that can use credentials presents every valid stolen
        credential from any node the attacker holds with a route out, and
        takes the service. Expired credentials are dropped first."""
        ttl = int(self.o.cred_ttl)
        for m_ in list(self._stolen):
            rec = self._stolen[m_]
            if ttl < 9999:
                for j in [x for x, t0 in rec.items() if tick - t0 > ttl]:
                    del rec[j]
            if not rec:
                del self._stolen[m_]
        if not (self._stages and self._k_cred and self._stolen):
            return
        st = self.state
        held = (st == COMPROMISED) & ~self.isolated & self._ord & self._contact
        if self.o.down_inert:
            held &= ~self._down
        if not held.any():
            return
        for m_ in list(self._stolen):
            if st[m_] == COMPROMISED:
                continue
            st[m_] = COMPROMISED
            self.comp_ref[m_] = self.atk_reference
            self._cause[m_] = 3
            self.n_spent += 1

    def _rotate(self, j: int):
        """The team has cleaned or rebuilt node j: its stolen credentials are
        rotated (rotate >= 1), and with rotate = 2 every stolen credential of
        each service it held, wherever it was taken from."""
        r = int(self.o.rotate)
        if r <= 0:
            return
        for m_ in list(self._stolen):
            rec = self._stolen[m_]
            if r >= 2 and m_ in self._cred_of.get(j, ()):
                rec.clear()
            else:
                rec.pop(j, None)
            if not rec:
                del self._stolen[m_]

    def _source_reference(self, tick: int) -> int:
        """The persistent source issues a new reference every `retool` ticks. In
        4B that period is the structural tempo; here it can be set on its own."""
        period = self.o.retool if self.o.retool else self.cfg.strategic_cycle
        ref = 10_000 + tick // max(1, int(period))
        self.first_seen_ref.setdefault(ref, tick)
        return ref

    # ---- dependency threshold ----------------------------------------------
    def _theta_ok(self, j: int, rc: RelationClass) -> bool:
        """theta = any: one compromised supplier is enough (the frozen core).
        majority / all: a delivery of class rc is accepted only once more than
        half / all of j's live suppliers of that class are compromised."""
        if self.theta == "any" or rc not in THETA_CLASSES:
            return True
        en = self.rel_enabled[rc]
        live = [i for i in self._sup[rc].get(j, ()) if en[i, j]]
        if not live:
            return False
        share = sum(1 for i in live if self.state[i] == COMPROMISED) / len(live)
        return share > 0.5 if self.theta == "majority" else share >= 1.0

    # ---- propagation ----------------------------------------------------------
    def _disable_relation(self, rc: RelationClass, i: int, j: int):
        super()._disable_relation(rc, i, j)
        self._flat_cache.pop(i, None)

    def _flat(self, i: int) -> list:
        """The (class, receiver) pairs node i delivers on, in exactly the order
        Engine4B._deliver visits them. Cached until one of i's relations changes."""
        f = self._flat_cache.get(i)
        if f is None:
            f = [(rc, j) for rc in RelationClass if rc is not CONFERRING
                 for j in self.adj[rc].get(i, ())]
            self._flat_cache[i] = f
        return f

    def _deliver(self, tick: int):
        """Engine4B._deliver, same visits in the same order, written as one loop
        (the per-offer function call and array look-ups dominated run time).
        Adds: the theta check, and a node whose interface is closed refuses
        Connection deliveries."""
        self._update_plane_ownership(tick)
        state = self.state
        comp = state == COMPROMISED
        infected = self._inf_ref >= 0
        blocked = (comp | self.isolated | infected).tolist()
        rec = self._rec3 if self._stages else self._rec
        ch_needs = CLASS_NEEDS[CHANNEL]
        isolated = self.isolated.tolist()
        closed = self._closed
        plane_of, owned, resident = self.plane_of, self.owned_plane, self.resident
        theta_on = self.theta != "any"
        rollout = self._has_rollout
        comp_ref = self.comp_ref
        src = self.source

        def offers(i, ref, conn_only=False, upgraded=False, only=None):
            for rc, j in (self._flat(i) if only is None else (only,)):
                if blocked[j]:
                    continue
                if conn_only and rc is not CONNECTION:
                    continue
                if rc is DIRECTING:
                    g = plane_of.get((i, j))
                    if g is None or not owned.get(g, False):
                        continue
                    if rollout and not self._rollout_ready(g, j, tick):
                        continue
                elif rc is CONNECTION and closed[j]:
                    continue
                if theta_on and not self._theta_ok(j, rc):
                    continue
                # a reconfigured node is a supplier: its Connections also carry
                # the Execution Pathway
                needs = ch_needs if (upgraded and rc is CONNECTION) else CLASS_NEEDS[rc]
                res = resident.get(j)
                if res is None or res.reference != ref:
                    res = Resident(stage=T1_INTERFACE, reference=ref, via=i)
                    res.needs = needs
                    resident[j] = res
                elif len(needs) < len(res.needs):
                    res.needs = needs

        if self._k_spread:
            inert = self._down if self.o.down_inert else None
            for i in np.flatnonzero(comp).tolist():
                if i == src or isolated[i] or (inert is not None and inert[i]):
                    continue
                r = comp_ref[i]
                offers(i, int(r) if r >= 0 else self.atk_reference, False, bool(rec[i]))
            if self._payload:
                # a dormant payload infects its neighbours over Connections
                for i in np.flatnonzero(infected).tolist():
                    if not isolated[i]:
                        offers(i, int(self._inf_ref[i]), True)
        elif self._k_moves:
            # a hands-on operator: a few moves per tick, each from one captured
            # node along one of its relations
            ctc = self._contact
            dead = self._down if self.o.down_inert else np.zeros(self.n, dtype=bool)
            held = [i for i in np.flatnonzero(comp).tolist()
                    if i != src and not isolated[i] and not self.hostile[i] and ctc[i] and not dead[i]]
            if held:
                pr = self._pay_rng
                for _ in range(max(1, int(self.cfg.atk_budget))):
                    i = held[int(pr.integers(0, len(held)))]
                    fl = self._flat(i)
                    if not fl:
                        continue
                    r = comp_ref[i]
                    offers(i, int(r) if r >= 0 else self.atk_reference, False, bool(rec[i]),
                           fl[int(pr.integers(0, len(fl)))])
        if src is not None and not isolated[src] and self._k_iface:
            offers(src, self._source_reference(tick))

    def _system_held(self, k: int) -> bool:
        """The automated defence of system k is in the attacker's hands: every
        master that carries it is captured, or (with roles) the zone's Active
        Directory or the estate's DNS is, since whoever holds those reconfigures
        the endpoints."""
        return all(self.state[m] == COMPROMISED for m in self._def_masters[k])

    def _control_planes(self) -> List[int]:
        return [m_ for m_ in self._id_master if m_ >= 0] + [m_ for ov in self._over for m_ in ov]

    def _update_exclusion(self):
        """The defender is excluded from exactly the nodes a captured Control
        Plane reaches (and has not been cut off from)."""
        ex = self._excl
        ex[:] = False
        en = self.rel_enabled[DIRECTING]
        for m_ in set(self._control_planes()):
            if self.state[m_] == COMPROMISED:
                ex |= en[m_]
        if self._stages and self._k_xctl:
            # External Trust: a compromised third party holding Authority is a
            # Control Plane over the nodes it directs
            for ch in self._channels:
                if ch["external"] and ch["kind"] == "ctl" and self.state[ch["server"]] == COMPROMISED:
                    for j, _fr in ch["served"]:
                        ex[j] = True

    def _ad_held(self, k: int) -> bool:
        """The defender is excluded from group k: a master control plane with
        authority over it (its Active Directory controller, the hypervisor
        beneath its servers, the device management over its endpoints) is
        captured."""
        im = self._id_master[k]
        if im >= 0 and self.state[im] == COMPROMISED:
            return True
        for m_ in self._over[k]:
            if self.state[m_] == COMPROMISED:
                return True
        return False

    def _dns_held(self) -> bool:
        """DNS is in the attacker's hands. DNS is a Channel: whoever holds it
        can stand in for the supplier of any Channel found by name, and the
        defender's signatures, themselves delivered that way, stop arriving. The
        defender is blocked, not excluded: the team keeps its access and can
        restore DNS like any other service."""
        d_ = self._dns
        return d_ >= 0 and self.state[d_] == COMPROMISED and not self.isolated[d_]

    # ---- the payload ---------------------------------------------------------
    def _props(self, ref: int) -> tuple:
        """(capability, delay) of the attack with this signature, drawn once."""
        p = self._ref_prop.get(ref)
        if p is None:
            o = self.o
            cap = self._attack_now()
            if o.cap_spread > 0:
                cap *= 1.0 + o.cap_spread * (2.0 * self._pay_rng.random() - 1.0)
            dormant = self._kind == "implant" or (
                self._kind in (None, "mixed", "malware") and o.dormant_share > 0
                and self._pay_rng.random() < o.dormant_share)
            dly = int(o.dormant_delay) if dormant else int(o.payload_delay)
            fixed = bool(dormant and o.fixed_clock > 0 and self._pay_rng.random() < o.fixed_clock)
            p = (max(cap, 1e-9), max(dly, 0), fixed)
            self._ref_prop[ref] = p
        return p

    def _control_alive(self, j: int) -> bool:
        """Node j carries a control that still answers to the defender."""
        if not self._has_control[j] or self._excl[j]:
            return False
        if self._stages and self._rec3[j]:
            return False                # stage 3: the attacker has disabled the agent
        k = int(self.cluster_of[j])
        return not (k >= 0 and self._system_held(k))

    def _repels(self, j: int, ref: int) -> bool:
        """Does node j's control repel a triggering payload? Only a node that
        carries the control, in a zone whose defence still stands, can."""
        if not self._control_alive(j):
            return False
        if ref in self.blacklist[j]:
            if not (self._stages and self.o.sig_block >= 0):
                return True
            if self._pol_rng.random() < self.o.sig_block:
                return True                      # the known signature matched
            # slipped the match: the capability contest still follows
        rule, D = self.o.cap_rule, float(self.o.def_cap)
        A = self._props(ref)[0] if self._payload else self._attack_now()
        if self._inf_capv[j] >= 0 and not self._stages:
            A = float(self._inf_capv[j])        # v0.13: a Channel's payload acts with no more than its ceiling
        if rule == "ratio":
            p = D / (D + A)
        elif rule == "cutoff":
            p = self.cfg.def_success_prob if A <= D else 0.0
        else:
            p = self.cfg.def_success_prob
        return bool(self._pol_rng.random() < p)

    def _seen_ref(self, ref: int, tick: int):
        """A node has repelled this attack, so the defender has seen it: a block
        for it is scheduled in every zone whose defence still stands."""
        if not self._sig or ref in self._known_refs:
            return                      # a malware-free intrusion gives the defender nothing to block
        self._known_refs.add(ref)
        for k in range(self.K):
            if not self._system_held(k):
                self.pending_blocks.append((tick + self.cfg.block_delay, ref, k))

    def _arrive_at(self, j: int, ref: int, cause: int, tick: int, ceil: float = -1.0):
        """A payload has completed its arrival at node j by whatever route. On a
        Channel (ceil >= 0) it acts with no more than the Channel's ceiling, and
        a rating above the ceiling raises an alarm on a node with a live control;
        on a visible node the defender then resolves it by hand."""
        self._inf_capv[j] = -1.0
        if ceil >= 0 and self._stages:
            # the Authority the Channel makes available; nothing is announced
            # on arrival. An alarm comes only from an attempt above it
            self._inf_capv[j] = float(ceil)
        elif ceil >= 0:
            rating = self._props(ref)[0] if self._payload else self._attack_now()
            self._inf_capv[j] = min(rating, ceil)
            if rating > ceil and self._control_alive(j):
                self.n_alarms += 1
                if self.net.visible[j] and self._alarm[j] < 0:
                    self._alarm[j] = tick
                    self._seen[j] = tick
                    self._seen_ref(ref, tick)
        if self._payload:
            _cap, dly, fixed = self._props(ref)
            # the same variable set two ways: this node's arrival plus the delay,
            # or one fixed tick for every node the attack infects
            due = (self.first_seen_ref.get(ref, tick) + dly) if fixed else (tick + dly)
            self._inf_ref[j] = ref
            self._inf_due[j] = max(due, tick)
            self._cause[j] = cause
            self.n_infected += 1
            return
        if self._roles and cause == 2 and self._repels(j, ref):
            if self._sig:
                self.blacklist[j].add(ref)
            self.n_repelled += 1
            if self.net.visible[j] or not self._stages:
                self._seen_ref(ref, tick)        # an invisible node's discovery goes nowhere (v0.18)
            return
        self.state[j] = COMPROMISED
        self.comp_ref[j] = ref
        self._cause[j] = cause

    def _advance_residents(self, tick: int):
        if not self._payload:
            return super()._advance_residents(tick)
        before = self.state == COMPROMISED
        via = {j: res.via for j, res in self.resident.items()}
        super()._advance_residents(tick)
        new = np.flatnonzero((self.state == COMPROMISED) & ~before)
        for j in new.tolist():
            ref = int(self.comp_ref[j])
            self.state[j] = 0
            self.comp_ref[j] = -1
            # Initial Access (from outside, cause 4) or Lateral Movement (cause 1)
            self._arrive_at(j, ref, 4 if via.get(j) == self.source else 1, tick)

    def _trigger(self, tick: int):
        """Payloads whose delay has expired trigger, and the node answers."""
        due = np.flatnonzero((self._inf_ref >= 0) & (self._inf_due <= tick))
        for j in due.tolist():
            ref = int(self._inf_ref[j])
            self._inf_ref[j] = -1
            if self.isolated[j] or self.state[j] == COMPROMISED:
                continue
            if self._repels(j, ref):
                if self._sig:
                    self.blacklist[j].add(ref)
                self.n_repelled += 1
                self._cause[j] = 0
                if self.net.visible[j] or not self._stages:
                    self._seen_ref(ref, tick)    # an invisible node's discovery goes nowhere (v0.18)
            else:
                self.state[j] = COMPROMISED
                self.comp_ref[j] = ref
                if self._stages:
                    # Persistence: by Connection the payload won the node's own
                    # Authority; by Channel it holds the Channel's ceiling
                    c_ = float(self._inf_capv[j])
                    self._L[j] = float(self.o.auth_conn) if c_ < 0 else c_
                    self._norec[j] = False
                    self._tried_x[j] = False
                    if self._L[j] < self._want and self.o.route_esc:
                        self._escalate(j, ref, tick)
                else:
                    # a payload that came down a Channel does not reconfigure the node
                    self._norec[j] = bool(self._inf_capv[j] >= 0)
                if self._phase == "stealer":
                    self._harvest.add(j)
                    if self._stages:
                        self._steal_from(j, tick, by_stealer=True)

    def _retool_retry(self, tick: int):
        """A new payload from the source executes on every foothold the attacker
        holds and tries to escalate there (v0.18). Once per new reference."""
        ref = self._source_reference(tick)
        if ref == self._last_retry_ref:
            return
        self._last_retry_ref = ref
        self._spend_credentials(tick)            # v0.21: the new payload uses what was stolen
        if not (self._stages and self.o.retry and self.o.route_esc):
            return
        held = (self.state == COMPROMISED) & ~self.isolated & self._ord & (self._L < self._want)
        for j in np.flatnonzero(held).tolist():
            if ref in self.blacklist[j]:
                continue                         # this payload is already blocked on the node
            self.comp_ref[j] = ref               # the foothold now carries the new payload
            self._escalate(j, ref, tick)

    def _escalate(self, j: int, ref: int, tick: int):
        """Privilege Escalation: the payload attempts an action above the
        Authority it arrived with. The node's control, if it still answers,
        contests it and raises an alarm; a won attempt gives the node's
        Authority."""
        self.n_esc += 1
        win = True
        if self._control_alive(j):
            self.n_alarms += 1
            if self.net.visible[j] and self._alarm[j] < 0:
                self._alarm[j] = tick
                if not self._queue:
                    self._seen[j] = tick
                    self._seen_ref(ref, tick)
            rule, D = self.o.cap_rule, float(self.o.def_cap)
            A = self._props(ref)[0]
            if rule == "ratio":
                p = A / (D + A)
            elif rule == "cutoff":
                p = 1.0 - self.cfg.def_success_prob if A <= D else 1.0
            else:
                p = 1.0 - self.cfg.def_success_prob
            win = bool(self._pol_rng.random() < p)
        if win:
            self._L[j] = 100.0
            self.n_esc_won += 1
            self._stage2(j, tick)

    def _stage2(self, j: int, tick: int):
        """The node is the attacker's: unreclaimable in place, out of service
        until rebuilt, and its data has a second chance to leave."""
        if self._nrec >= 0:
            self._rec[j] = True
        if self.o.stage_down:
            self._down[j] = True
        if self._steal and not self._exfil[j] and self._contact[j]:
            if self._pay_rng.random() < self.o.exfil_esc:
                self._exfil[j] = True

    def _contact_update(self):
        """Command and Control: the held nodes the operator can reach, which
        are those with a route out and those joined to one through held
        nodes."""
        held = (self.state == COMPROMISED) & ~self.isolated & ~self.hostile
        ct = held & self._egress
        if ct.any() and not ct[held].all():
            adj = self.adj[CONNECTION]
            stack = np.flatnonzero(ct).tolist()
            while stack:
                i = stack.pop()
                for j in adj.get(i, ()):
                    if held[j] and not ct[j]:
                        ct[j] = True
                        stack.append(j)
        self._contact = ct

    def _impact_step(self, tick: int):
        """Exfiltration and Impact. A stealing payload makes one attempt to
        send a held node's data out, where the operator has a route; a
        destructive payload with the Authority for it takes the node out of
        service. Both come after the node has been held node_reconf ticks."""
        comp = self.state == COMPROMISED
        self._L[~comp] = 0.0
        self._down &= comp
        if self._nrec < 0:
            return
        ct = self._comp_tick
        ripe = comp & ~self.isolated & self._ord & (ct >= 0) & ((tick - ct) >= self._nrec)
        if self._steal:
            # stage 1: one attempt against the control that protects data; if
            # it holds, it keeps holding for this hold of the node
            for j in np.flatnonzero(ripe & ~self._tried_x & ~self._exfil & self._contact).tolist():
                self._tried_x[j] = True
                if self._pay_rng.random() < self.o.exfil_p:
                    self._exfil[j] = True
        if self._destroy and not self.o.stage_down:
            self._down |= ripe & (self._L >= self.o.auth_destroy)
        # stage 3: held at stage 2 for node_reconf ticks
        self._rec3 &= comp
        self._rec3 |= self._rec & comp & ~self.isolated & (self._t2 >= 0) & ((tick - self._t2) >= self._nrec)

    # ---- master controllers ---------------------------------------------------
    def _controller_step(self, tick: int):
        """A controller is taken through its privileged credential: the capture
        of a node that holds it gives the attacker the controller. A captured
        controller's authority reaches the controllers it is linked to after the
        replication delay."""
        st, iso = self.state, self.isolated
        need_rec = self._nrec >= 0
        stg = self._stages
        if stg:
            # Credential Access: the attacker holds the node with enough
            # Authority, has held it long enough to act, and can reach it
            ct = self._comp_tick
            ok = (st == COMPROMISED) & ~iso & (self._L >= self.o.auth_cred) & self._contact
            if self.o.down_inert:
                ok &= ~self._down
            if need_rec:
                ok &= (ct >= 0) & ((tick - ct) >= self._nrec)
        for m_, nodes in (self._cred.items() if self._k_cred else ()):
            if st[m_] == COMPROMISED:
                continue
            for j in nodes:
                # v0.13: the credential is harvested only from a node the
                # attacker has held long enough to reconfigure
                if (ok[j] if stg else
                        (st[j] == COMPROMISED and not iso[j] and (self._rec[j] or not need_rec))):
                    st[m_] = COMPROMISED
                    self.comp_ref[m_] = self.comp_ref[j] if self.comp_ref[j] >= 0 else self.atk_reference
                    self._cause[m_] = 3
                    if stg:
                        self._steal_from(j, tick, by_stealer=False)   # v0.21: the credential is kept
                    break
        for m_ in self.masters:
            if st[m_] == COMPROMISED:
                self._cap_tick.setdefault(m_, tick)
        link, rd = int(self.o.ctl_link), int(self.o.repl_delay)
        if link <= 0 or rd < 0 or rd >= self.cfg.horizon:
            return
        for ms in self._kinds:
            nz = len(ms)
            held = [(i, m_) for i, m_ in enumerate(ms) if st[m_] == COMPROMISED]
            if not held or len(held) == nz:
                continue
            for i, m_ in enumerate(ms):
                if st[m_] == COMPROMISED:
                    continue
                for i2, m2 in held:
                    near = link >= 2 or abs(i - i2) in (1, nz - 1)
                    if near and tick - self._cap_tick[m2] >= rd:
                        st[m_] = COMPROMISED
                        self.comp_ref[m_] = self.comp_ref[m2]
                        self._cause[m_] = 3
                        self._cap_tick[m_] = tick
                        break

    def _channel_push(self, tick: int):
        """A captured delivery channel delivers the attacker's payload to the
        nodes it serves, in its delivery order if the rollout is staged. So does
        a compromised external supplier, and a compromised external trusted
        party over its authority."""
        st, iso = self.state, self.isolated
        stage = int(self.o.stage_time)
        dns_held = self._dns_held()
        for ci, ch in enumerate(self._channels):
            s_ = ch["server"]
            if ch["external"]:
                if st[s_] != COMPROMISED or not (self._k_xctl if ch["kind"] == "ctl" else self._k_xchan):
                    continue            # this party is not compromised, or this kind does not use it
                ref, unbound = self._source_reference(tick), False
            else:
                if not self._k_ichan:
                    continue
                own = st[s_] == COMPROMISED and not iso[s_] and bool(self._contact[s_]) \
                    and not (self.o.down_inert and self._down[s_])
                if not own and not (dns_held and not ch["verified"]):
                    continue            # the attacker holds neither the channel's server nor, for a
                                        # channel that does not verify its supplier, DNS
                ref = int(self.comp_ref[s_]) if (own and self.comp_ref[s_] >= 0) else self.atk_reference
                unbound = bool(self._excl[s_])
            el = tick - self._ch_start.setdefault((ci, ref), tick)
            ctl = ch["kind"] == "ctl"
            if ctl and self._stages:
                # External Trust: the party holds Authority, so its push is a
                # reconfiguration, as a captured Control Plane's is
                if el >= self._reconf:
                    for j, frac in ch["served"]:
                        if st[j] == COMPROMISED or iso[j] or ref in self.blacklist[j]:
                            continue
                        st[j] = COMPROMISED
                        self.comp_ref[j] = ref
                        self._cause[j] = 3
                        self._inf_ref[j] = -1
                        self._L[j] = 100.0
                        self._tried_x[j] = False
                        if self._nrec >= 0:
                            self._rec[j] = True
                continue
            for j, frac in ch["served"]:
                if st[j] == COMPROMISED or iso[j] or self._inf_ref[j] >= 0:
                    continue
                key = (ci, ref, j)
                if key in self._ch_tried:
                    continue
                if ctl:
                    if el < self._reconf:
                        continue
                elif not unbound and el < frac * stage:
                    continue
                self._ch_tried.add(key)
                if ref in self.blacklist[j]:
                    continue
                # a Channel's payload is guaranteed to run: the Channel bypasses
                # the node's own parameters because it inherits them
                self._arrive_at(j, ref, 3 if ctl else 2, tick, -1.0 if ctl else ch["ceil"])

    def _hand_updates(self, tick: int):
        if not self._hand_pending:
            return
        keep = []
        for (t, ref, k) in self._hand_pending:
            if t > tick:
                keep.append((t, ref, k))
                continue
            for j in self._hand[k]:
                self.blacklist[j].add(ref)
                if self._inf_ref[j] == ref:
                    self._inf_ref[j] = -1
        self._hand_pending = keep

    def _reconfigure(self, tick: int):
        """A node held for long enough has been reconfigured by the attacker."""
        comp = self.state == COMPROMISED
        self._rec &= comp
        self._norec &= comp
        if self._nrec >= 0:
            ct = self._comp_tick
            if self._stages:
                # a node is reconfigured (stage 2) by a won escalation, a Control
                # Plane's push or External Trust; holding a foothold long enough
                # no longer does it on its own
                can = self._L >= self.o.auth_reconf
                self._rec |= comp & ~self.isolated & can & (ct >= 0) & ((tick - ct) >= self._nrec) \
                    & (self._L >= 100.0)
            else:
                self._rec |= comp & ~self.isolated & ~self._norec & (ct >= 0) & ((tick - ct) >= self._nrec)
        if self._stages:
            self._t2[~self._rec] = -1
            self._t2[self._rec & (self._t2 < 0)] = tick

    def _master_push(self, tick: int):
        if self._mr_on:
            # a capture takes effect on the tick it happens
            for m in self.masters:
                if self.state[m] == COMPROMISED:
                    self.owned_masters.add(m)
            self.attacker_owns_master = bool(self.owned_masters)
            if self._roles:
                self._update_exclusion()
            if self.o.master_kills_sigs:
                for k in range(self.K):
                    if self._system_held(k):
                        for j in self.push_scope[k].tolist() + self._hand[k]:
                            if self.blacklist[j]:
                                self.blacklist[j].clear()
                for j in np.flatnonzero(self._excl).tolist():
                    if self.blacklist[j]:
                        self.blacklist[j].clear()
        for m in list(self.masters):
            if m not in self.owned_masters or self.isolated[m]:
                continue
            if self._two_track and self.state[m] != COMPROMISED:
                self.owned_masters.discard(m)     # a restored master is no longer the attacker's
                continue
            if self._reconf and tick - self._cap_tick.setdefault(m, tick) < self._reconf:
                continue                          # the attacker is still reconfiguring
            if self._roles and m in self._def_set:
                # endpoint detection is a Channel that also carries the defence:
                # its capture delivers the payload to the nodes it manages (and
                # their control, now the attacker's, cannot repel it); it is not
                # a reconfiguration of the estate
                if self._k_ichan:
                    for j in np.flatnonzero(self.rel_enabled[DIRECTING][m]).tolist():
                        if self.state[j] != COMPROMISED and not self.isolated[j] and self._inf_ref[j] < 0 \
                                and ("edr", m, self.atk_reference, j) not in self._ch_tried:
                            self._ch_tried.add(("edr", m, self.atk_reference, j))
                            self._arrive_at(j, self.atk_reference, 2, tick, float(self.o.ceil_edr))
                continue
            reach_ = self.rel_enabled[DIRECTING][m] if self._roles else self.net.access[DIRECTING][m]
            for j in np.flatnonzero(reach_):
                j = int(j)
                if self.state[j] == COMPROMISED or self.isolated[j]:
                    continue
                if self.atk_reference in self.blacklist[j]:
                    continue
                if self._has_rollout:
                    g = self.plane_of.get((m, j))
                    if g is not None and not self._rollout_ready(g, j, tick):
                        continue
                if not self._theta_ok(j, DIRECTING):
                    continue
                self.state[j] = COMPROMISED
                self.comp_ref[j] = self.atk_reference
                self._cause[j] = 3
                self._inf_ref[j] = -1
                self._norec[j] = False
                self._L[j] = 100.0
                self._tried_x[j] = False
                if self._nrec >= 0:
                    self._rec[j] = True           # the controller's push is the reconfiguration

    # ---- defenders -----------------------------------------------------------
    def _picture(self, d: Domain) -> np.ndarray:
        """What defender d can see now: compromised, visible, its own, not
        isolated, and compromised for at least the detection latency."""
        base = self._compromised_mask() & d.mask & ~self.isolated
        m = base & self._vis
        L = self.o.detect_latency
        if L > 0:
            ct = self._comp_tick
            m = m & (ct >= 0) & ((self._tick - ct) >= L)
        if self._blind_live:
            ct = self._comp_tick
            m = m | (base & ~self._vis & (ct >= 0)
                     & ((self._tick - ct) >= self.o.blind_delay))
        return m

    def _observe_dom(self, di: int) -> np.ndarray:
        d = self.domains[di]
        if self.o.obs_interval <= 1:
            return self._picture(d)
        snap = self._snap[di]
        if snap is None:
            return np.zeros(self.n, dtype=bool)
        # the defender acts on its last picture, minus what it has since dealt with
        return snap & self._compromised_mask() & ~self.isolated

    def _clean_controller_governs(self, j: int) -> bool:
        k = int(self.cluster_of[j])
        if k >= 0:
            for mk in self.masters_of[k]:
                if self.state[mk] != COMPROMISED and not self.isolated[mk]:
                    return True
        for c in self.controllers_of.get(j, ()):
            if self.state[c] != COMPROMISED and not self.isolated[c]:
                return True
        return False

    def _block_dom(self, di: int, tick: int):
        """A clean master detects the references behind the compromises its
        defender observes and schedules a block for its own system."""
        d = self.domains[di]
        if self._roles and self._dns_held():
            return                      # signatures and automated clean-up cannot be delivered
        ks = []
        if self._roles:
            # a group's blocks are issued while its endpoint detection console
            # (inside the estate or with a third party) is not the attacker's
            for k in range(self.K):
                if len(self.cluster_nodes[k]) and d.mask[int(self.cluster_nodes[k][0])] \
                        and not self._system_held(k):
                    ks.append(k)
        else:
            for m in d.masters:
                if m not in self._def_set:
                    continue
                k = int(self.cluster_of[m])
                if self.state[m] != COMPROMISED and k not in ks:
                    ks.append(k)
        if not ks:
            return
        obs = self._observe_dom(di)
        budget = d.tac_budget
        refs_seen = {int(self.comp_ref[j]) for j in np.flatnonzero(obs) if self.comp_ref[j] >= 0} \
            if self._sig else set()
        for ref in sorted(refs_seen):
            if budget <= 0:
                break
            for k in ks:
                self.pending_blocks.append((tick + self.cfg.block_delay, ref, k))
            budget -= 1
        if self.o.auto_clean:
            # automated track: the plane re-cleans covered nodes that hold a
            # reference they already block
            for k in ks:
                for j in self.push_scope[k].tolist():
                    if self.state[j] == COMPROMISED and not self.hostile[j] and not self._rec[j] \
                            and not self._excl[j] and not self._down[j] \
                            and not self.isolated[j] and int(self.comp_ref[j]) in self.blacklist[j]:
                        if self._success():
                            self._auto_reset(j)

    def _apply_pending_blocks(self, tick: int):
        if self._mr_on and self.o.master_kills_sigs and self.pending_blocks:
            self.pending_blocks = [b for b in self.pending_blocks if not self._system_held(b[2])]
        if self._roles and self._dns_held():
            return                      # blocks wait until DNS is restored
        still = []
        for (t, ref, k) in self.pending_blocks:
            if t > tick:
                still.append((t, ref, k))
                continue
            missed = False
            if self._hand[k] and (ref, k) not in self._hand_done:
                self._hand_done.add((ref, k))
                self._hand_pending.append((tick + int(self.o.hand_delay), ref, k))
            for j in self.push_scope[k].tolist():
                if ref in self.blacklist[j] or self._excl[j]:
                    continue
                if (self._stages and self.o.sig_block >= 0) or self._success():
                    self.blacklist[j].add(ref)       # a known signature reaches every agent
                    if self._inf_ref[j] == ref:
                        self._inf_ref[j] = -1      # a dormant payload with this signature is removed
                    if self.o.auto_clean and self.state[j] == COMPROMISED \
                            and not self.hostile[j] and not self.isolated[j] \
                            and not self._rec[j] and not self._down[j] and int(self.comp_ref[j]) == ref:
                        self._auto_reset(j)
                else:
                    missed = True
            if missed:
                still.append((tick + 1, ref, k))
        self.pending_blocks = still

    def _auto_reset(self, j: int):
        self._reset_node(j)
        self.owned_masters.discard(j)

    def _manual_dom(self, di: int, tick: int):
        """Manual track. The team takes the compromised nodes it can see in
        priority order. With a rebuild time each picked node is isolated at once
        and occupies one team slot until it returns; without one it is reset in
        place, as in 4B."""
        d = self.domains[di]
        obs = self._observe_dom(di)
        self.last_reset = set(x for x in self.last_reset if not d.mask[x])
        deg = lambda j: -len(self.adj[CONNECTION].get(int(j), ()))
        cands = np.flatnonzero(obs).tolist()
        q = self._rebuilding[di]
        if self._roles:
            # a payload that alarmed on a visible node is the team's to resolve,
            # even before it has triggered
            have = set(cands)
            cands += [j for j in np.flatnonzero((self._alarm >= 0) & d.mask & ~self.isolated).tolist()
                      if j not in have and (self._inf_ref[j] >= 0 or self.state[j] == COMPROMISED)]
        if self._track_seen:
            seen = self._seen
            lock = max(self._mdelay, self._lockout) if self._lock_live else self._mdelay
            ex = self._excl
            mset_ = self._master_set
            cands = [j for j in cands if seen[j] >= 0 and
                     tick - seen[j] >= (self._mdelay if j in mset_ else (lock if ex[j] else self._mdelay))]
        if self._mr_on:
            # a captured master cannot be reset or isolated, only rebuilt from
            # outside the plane; it stays in the attacker's hands meanwhile
            mset = self._master_set
            inq = {j for _, j in q}
            mr = int(self.o.master_rebuild)
            for j in [j for j in cands if j in mset and j not in inq]:
                if len(q) >= d.tac_budget:
                    break
                if mr < self.cfg.horizon:
                    q.append((tick + mr, int(j)))
            cands = [j for j in cands if j not in mset]
        if self.o.manual_scope:
            # the team leaves to automation what automation can fix; an alarm
            # is always the team's
            cands = [j for j in cands if self._alarm[j] >= 0 or not self._auto_available(j)]
        if self.o.priority:
            order = sorted(cands, key=lambda j: (self._tier[j], deg(j)))
        else:
            order = self._order(cands, key=deg)
        if not self._manual:
            budget = d.tac_budget - len(q)
            for j in order:
                if budget <= 0:
                    break
                if self._success():
                    self._auto_reset(int(j))
                budget -= 1
            return
        for j in order[:max(d.tac_budget - len(q), 0)]:
            self._isolate_node(int(j))
            self._inf_ref[j] = -1
            self._alarm[j] = -1
            q.append((tick + int(self.o.rebuild_time), int(j)))

    def _finish_rebuilds(self, tick: int):
        for di, q in enumerate(self._rebuilding):
            if not q:
                continue
            keep = []
            for (t, j) in q:
                if t > tick:
                    keep.append((t, j))
                    continue
                self.isolated[j] = False
                if self._success():
                    self._auto_reset(j)        # back in service, clean
            self._rebuilding[di] = keep

    # ---- the team's single queue of work (v0.14) ---------------------------------
    def _job(self, kind: str, key, prio: float, tick: int, **kw):
        k = (kind, key)
        if k in self._job_keys:
            return
        self._job_keys.add(k)
        self._jobs.append(dict(kind=kind, key=key, prio=float(prio), made=tick, left=-1, **kw))

    def _queue_step(self, tick: int):
        """One hour of the team's work. Everything it does is a job with a
        duration, done by a fixed number of responders: investigating an alarm
        or a reported compromise, cleaning a node, rebuilding one that was
        reconfigured or taken out (or restoring a captured console or DNS), and
        cutting a relation. Work beyond the team's capacity waits, so pick-up
        and response slow in proportion to the backlog."""
        d = self.domains[0]
        st, iso, inf = self.state, self.isolated, self._inf_ref
        if tick % d.tactical_cycle == 0:
            self.last_reset = set()
        live = lambda j: st[j] == COMPROMISED or inf[j] >= 0
        # ---- work in hand moves on by an hour
        keep = []
        for jb in self._jobs:
            if jb["left"] < 0:
                keep.append(jb)
                continue
            jb["left"] -= 1
            if jb["left"] > 0:
                keep.append(jb)
                continue
            self._job_done(jb, tick)
        self._jobs = keep
        # ---- new work: what has been reported is investigated first
        comp = st == COMPROMISED
        self._known &= comp | (inf >= 0)
        rep_ = self._observe_dom(0) | ((self._alarm >= 0) & d.mask & ~iso & (comp | (inf >= 0)))
        for j in np.flatnonzero(rep_ & ~self._known).tolist():
            self._job("inv", j, self._pval[j], tick, node=j)
        cps = self._cp_set
        scope = bool(self.o.manual_scope)
        for j in np.flatnonzero(self._known & d.mask & ~iso).tolist():
            if (j in cps and not self._cp_rebuild) or self._excl[j]:
                continue                # a captured Control Plane is not rebuilt (the rule); an excluded node cannot be reached
            if scope and self._alarm[j] < 0 and self._auto_available(j):
                continue                # left to the automated track
            self._job("fix", j, self._pval[j], tick, node=j)
        # ---- free responders take the waiting work in order
        busy = sum(1 for jb in self._jobs if jb["left"] >= 0)
        free = int(d.tac_budget) - busy
        waiting = [jb for jb in self._jobs if jb["left"] < 0]
        if len(waiting) > self.q_max:
            self.q_max = len(waiting)
        if free > 0 and waiting:
            od = self.o.queue_order
            if od == "fifo":
                waiting.sort(key=lambda jb: jb["made"])
            elif od == "degree":
                waiting.sort(key=lambda jb: (-len(self.adj[CONNECTION].get(int(jb.get("node", 0)), ())), jb["made"]))
            else:
                waiting.sort(key=lambda jb: (-jb["prio"], jb["made"]))
            done_now = []
            for jb in waiting:
                if free <= 0:
                    break
                kind = jb["kind"]
                if kind in ("inv", "fix"):
                    j = jb["node"]
                    if not live(j) or iso[j]:
                        done_now.append(jb)          # nothing left to do
                        continue
                    if kind == "fix" and j in self._cp_set and not self._cp_rebuild:
                        done_now.append(jb)
                        continue
                    if kind == "fix" and self._excl[j]:
                        continue                     # cannot be reached; waits without holding anyone
                if kind == "inv":
                    jb["left"] = self._mdelay
                elif kind == "cut":
                    jb["left"] = max(0, int(self.o.t_cut))
                else:
                    # containment comes first: the node is isolated when the
                    # work on it starts, and returns when the work is done. A
                    # node that was reconfigured or taken out, or a service,
                    # needs a rebuild; any other is cleaned
                    hard = self._rec[j] or self._down[j] or j in self._svc_set
                    jb["hard"] = bool(hard)
                    if j in self._cp_set:
                        # sensitivity only: a Control Plane is rebuilt from outside and
                        # stays in the attacker's hands until the rebuild is done
                        jb["left"] = max(0, int(self.o.master_rebuild))
                    else:
                        self._isolate_node(j)
                        inf[j] = -1
                        jb["left"] = max(0, int(self.o.rebuild_time if hard else self.o.t_clean))
                free -= 1
                self.q_started += 1
                self.q_wait += tick - jb["made"]
                if jb["left"] <= 0:
                    self._job_done(jb, tick)
                    done_now.append(jb)
            if done_now:
                ids = set(id(x) for x in done_now)
                for jb in done_now:
                    self._job_keys.discard((jb["kind"], jb["key"]))
                self._jobs = [jb for jb in self._jobs if id(jb) not in ids]

    def _job_done(self, jb: dict, tick: int):
        self._job_keys.discard((jb["kind"], jb["key"]))
        kind = jb["kind"]
        st, inf = self.state, self._inf_ref
        if kind == "cut":
            self._cut_apply(jb["cut"])
            return
        j = jb["node"]
        if kind == "inv":
            if st[j] == COMPROMISED or inf[j] >= 0:
                self._known[j] = True
                self._evid.add(j)
                ref = int(inf[j]) if inf[j] >= 0 else int(self.comp_ref[j])
                if self._alarm[j] >= 0 and ref >= 0:
                    self._seen_ref(ref, tick)        # the investigation yields the signature, if there is one
                    if self._stages and self.o.hunt:
                        # hunt on alarm: every node with an agent that holds this
                        # payload is now known and queued, visible or not
                        same = ((st == COMPROMISED) & (self.comp_ref == ref)) | (inf == ref)
                        same &= self._has_control & ~self.isolated & ~self._known
                        for h in np.flatnonzero(same).tolist():
                            self._known[h] = True
                            self._evid.add(h)
                            self.n_hunt += 1
            return
        self.isolated[j] = False
        if st[j] != COMPROMISED:
            self._alarm[j] = -1                      # it held only a payload that had not triggered: removed
            self._known[j] = False
            return
        if self._excl[j]:
            return
        if self._success():
            self._auto_reset(j)
            inf[j] = -1
            self._alarm[j] = -1
            self._known[j] = False
            self._down[j] = False
            self._L[j] = 0.0
            self._rec3[j] = False
            self._t2[j] = -1
            self._rotate(j)                          # v0.21
            if j in self._cp_set:
                self._cap_tick.pop(j, None)
                self._update_exclusion()

    def _cut_apply(self, c: tuple):
        if c[0] == "rel":
            _t, rc, i, j = c
            self._disable_relation(rc, i, j)
            self.severed.add((rc, i, j))
        elif c[0] == "chan":
            _t, ci, j = c
            ch = self._channels[ci]
            ch["served"] = [(x, fr) for x, fr in ch["served"] if x != j]
        elif c[0] == "plane":
            _t, g = c
            ctl, members = self.net.control_planes[g]
            for m in members:
                if self.domains[0].mask[int(m)]:
                    self._disable_relation(DIRECTING, int(ctl), int(m))
            self.owned_plane[g] = False

    def _adapt_roles(self, di: int, tick: int):
        """Structural adaptation on the 4C estate. The defender cuts only on
        evidence: a node it has investigated (or, without the queue, seen)
        compromised. With the queue each cut is a job for the team."""
        d = self.domains[di]
        ev = self._evid if self._queue else self.ever_seen_comp
        st = self.state
        budget = d.strat_budget
        cuts = []
        # the entry relations of nodes found compromised
        for rc in RelationClass:
            for j in list(self.adj[rc].get(self.source, ())):
                if d.mask[j] and int(j) in ev:
                    cuts.append((("rel", rc, int(self.source), int(j)), int(j)))
        # a delivery Channel found to have carried an attack is withdrawn
        hit: Dict[int, bool] = {}
        for key in self._ch_tried:
            if not isinstance(key[0], str) and key[2] in ev:
                hit[key[0]] = True
        for ci in sorted(hit):
            for j, _fr in self._channels[ci]["served"]:
                if d.mask[j]:
                    cuts.append((("chan", ci, int(j)), int(j)))
        for g, (ctl, members) in self.net.control_planes.items():
            mem_idx = [int(m) for m in members if d.mask[int(m)]]
            if mem_idx and self.owned_plane.get(g, False) and any(m in ev for m in mem_idx):
                cuts.append((("plane", g), mem_idx[0]))
        # relations out of a node found compromised into a clean one
        master_set = set(self.masters)
        bridges = []
        for rc in RelationClass:
            for i in sorted(ev):
                if st[i] != COMPROMISED:
                    continue
                for j in list(self.adj[rc].get(i, ())):
                    if d.mask[j] and st[j] != COMPROMISED and not self.isolated[j]:
                        prio = 0 if (i in master_set or j in master_set or rc == DIRECTING) else 1
                        bridges.append((prio, rc, int(i), int(j)))
        bridges.sort(key=lambda t: t[0])
        cuts += [(("rel", rc, i, j), j) for _p, rc, i, j in bridges]
        for c, j in cuts:
            if budget <= 0:
                break
            if self._queue:
                if ("cut", c) in self._job_keys:
                    continue
                self._job("cut", c, self._pval[j], tick, cut=c)
            else:
                self._cut_apply(c)
            budget -= 1

    def _tactical_dom(self, di: int, tick: int):
        if self._manual or self.o.priority or self.o.manual_scope or self._mr_on or self._track_seen:
            return self._manual_dom(di, tick)
        d = self.domains[di]
        obs = self._observe_dom(di)
        budget = d.tac_budget
        # forget this defender's previous resets (the attacker's re-establishment
        # window is the last tactical action)
        self.last_reset = set(x for x in self.last_reset if not d.mask[x])
        if not self.cfg.gated_recovery:
            order = self._order(np.flatnonzero(obs).tolist(),
                                key=lambda j: -len(self.adj[CONNECTION].get(int(j), ())))
            for j in order:
                if budget <= 0:
                    break
                if self._success():
                    self._reset_node(int(j))
                budget -= 1
            return
        comp_obs = [int(j) for j in np.flatnonzero(obs)]
        for sn in d.masters:
            if budget <= 0:
                break
            if self.state[sn] == COMPROMISED and not self.isolated[sn]:
                self._isolate_node(sn)
                budget -= 1
        recoverable = self._order([j for j in comp_obs if self._clean_controller_governs(j)],
                                  key=lambda j: -len(self.adj[CONNECTION].get(j, ())))
        for j in recoverable:
            if budget <= 0:
                break
            if self._success():
                self._reset_node(j)
            budget -= 1
        if budget > 0:
            for j in comp_obs:
                if budget <= 0:
                    break
                if self.state[j] == COMPROMISED and not self.isolated[j] \
                        and not self._clean_controller_governs(j):
                    self._isolate_node(j)
                    budget -= 1

    def _note_observed(self):
        if self._track_seen:
            seen = self._seen
            self._alarm[(self.state != COMPROMISED) & (self._inf_ref < 0)] = -1
            seen[(self.state != COMPROMISED) & (self._alarm < 0)] = -1
            for di in range(len(self.domains)):
                obs = self._observe_dom(di)
                for j in np.flatnonzero(obs):
                    self.ever_seen_comp.add(int(j))
                seen[obs & (seen < 0)] = self._tick
            return
        for di in range(len(self.domains)):
            for j in np.flatnonzero(self._observe_dom(di)):
                self.ever_seen_comp.add(int(j))

    def _adapt_dom(self, di: int, tick: int):
        """Reactive structural adaptation (4B doctrine v3), confined to what this
        defender governs. It may cut or revoke a relation INTO one of its own
        nodes, whoever the supplier is; it never resets a node it does not govern.
          (1) cut the hostile source's delivery edges into its nodes;
          (2) revoke trust: disable a captured directing plane for its members;
          (3) reconfigure: cut compromised -> clean edges into its nodes
              (all classes, so a Channel or a conferring relation from a
              compromised supplier is withdrawn, and a node whose corner had
              that single supplier loses the corner)."""
        if self._roles:
            return self._adapt_roles(di, tick)
        d = self.domains[di]
        for rc in RelationClass:
            for j in list(self.adj[rc].get(self.source, ())):
                if d.mask[j]:
                    self._disable_relation(rc, int(self.source), int(j))
                    self.severed.add((rc, int(self.source), int(j)))
        # cut a delivery relation: a Channel that has delivered an attack into
        # this defender's nodes is withdrawn from them, within the same budget
        budget = d.strat_budget
        for ci, ch in enumerate(self._channels):
            if budget <= 0:
                break
            if not any(key[0] == ci for key in self._ch_tried if not isinstance(key[0], str)):
                continue
            keep = []
            for j, fr in ch["served"]:
                if budget > 0 and d.mask[j]:
                    budget -= 1
                else:
                    keep.append((j, fr))
            ch["served"] = keep
        budget = d.strat_budget
        for g, (ctl, members) in self.net.control_planes.items():
            if budget <= 0:
                break
            mem_idx = [int(m) for m in members if d.mask[int(m)]]
            if not mem_idx:
                continue
            seen = any(m in self.ever_seen_comp for m in mem_idx)
            if self.owned_plane.get(g, False) and seen:
                for m in mem_idx:
                    self._disable_relation(DIRECTING, int(ctl), m)
                self.owned_plane[g] = False
                budget -= 1
        budget = d.strat_budget
        comp = self._compromised_mask()
        master_set = set(self.masters)
        bridges = []
        for rc in RelationClass:
            for i in np.flatnonzero(comp).tolist():
                for j in list(self.adj[rc].get(i, ())):
                    if not d.mask[j]:
                        continue
                    if self.state[j] != COMPROMISED and not self.isolated[j]:
                        touches_master = (i in master_set) or (j in master_set)
                        prio = 0 if (touches_master or rc == DIRECTING) else 1
                        bridges.append((prio, rc, int(i), int(j)))
        bridges.sort(key=lambda t: t[0])
        for _prio, rc, i, j in bridges:
            if budget <= 0:
                break
            self._disable_relation(rc, i, j)
            self.severed.add((rc, i, j))
            budget -= 1

    # ---- attacker (Engine4B._attacker with several masters) -------------------
    def _attacker(self, tick: int):
        comp = self._compromised_mask()
        budget = self.cfg.atk_budget
        for m in self.masters:
            if self.state[m] == COMPROMISED:
                self.owned_masters.add(m)
        self.attacker_owns_master = bool(self.owned_masters)
        for j in list(self.last_reset):
            if budget <= 0:
                break
            if self.state[j] != COMPROMISED and not self.isolated[j]:
                if any(self.state[c] == COMPROMISED for c in self.controllers_of.get(j, ())):
                    self.state[j] = COMPROMISED
                    self.comp_ref[j] = self.atk_reference
                    budget -= 1
        if budget > 0:
            for rc in RelationClass:
                orig = self.net.access[rc]
                for i in np.flatnonzero(comp).tolist():
                    if budget <= 0:
                        break
                    if i == self.source:
                        continue
                    row_now = self.rel_enabled[rc][i]
                    cut = np.flatnonzero(orig[i] & ~row_now)
                    for j in cut.tolist():
                        if budget <= 0:
                            break
                        if (rc, i, int(j)) in self.severed:
                            continue
                        if self.state[j] != COMPROMISED and not self.isolated[j]:
                            self.rel_enabled[rc][i, j] = True
                            self.adj[rc].setdefault(i, set()).add(j)
                            self._flat_cache.pop(i, None)
                            budget -= 1
        if self.o.retool_fix:
            ref = self.atk_reference
            held = np.flatnonzero(comp & self._carries)
            if held.size:
                blocked = all(ref in self.blacklist[j] for j in held.tolist())
            else:
                cl = np.flatnonzero(self._carries & ~comp & ~self.isolated)
                blocked = bool(cl.size) and \
                    sum(1 for j in cl.tolist() if ref in self.blacklist[j]) * 2 > cl.size
        else:
            blocked = comp.any() and all(self.atk_reference in self.blacklist[j]
                                         for j in np.flatnonzero(comp))
        if blocked:
            self.atk_reference = self._next_ref
            self._next_ref += 1
            self.first_seen_ref.setdefault(self.atk_reference, tick)
            self.comp_ref[self._compromised_mask()] = self.atk_reference

    # ---- main loop -------------------------------------------------------------
    def run(self) -> Record:
        cfg = self.cfg
        if not cfg.strategic_reconfigure or cfg.blind_mode or cfg.drift_rate > 0:
            raise ValueError("Engine4C runs the austere E8 configuration only "
                             "(strategic_reconfigure on, no blind mode, no drift)")
        O = max(1, int(self.o.obs_interval))
        nd = range(len(self.domains))
        for tick in range(1, cfg.horizon + 1):
            self._tick = tick
            if self._kind == "campaign" and self._phase == "stealer" and tick > int(self.o.handoff):
                self._apply_kind("intrusion")    # v0.21: the campaign's hands-on phase begins
                self._spend_credentials(tick)
            if self._c2:
                self._contact_update()
            self._deliver(tick)
            self._advance_residents(tick)
            if self._roles:
                if self._cred:
                    self._controller_step(tick)
            self._master_push(tick)
            if self._roles:
                if self._channels:
                    self._channel_push(tick)
                if self._payload:
                    self._trigger(tick)
                    self._retool_retry(tick)
                self._hand_updates(tick)
            self._apply_pending_blocks(tick)
            if self._manual or self._mr_on:
                self._finish_rebuilds(tick)
            if O > 1 and tick % O == 0:
                for di in nd:
                    self._snap[di] = self._picture(self.domains[di])
            self._note_observed()
            if cfg.defender_tactical:
                for di in nd:
                    if tick % self.domains[di].block_cycle == 0:
                        self._block_dom(di, tick)
            if self.adapt_on:
                for di in nd:
                    if tick % self.domains[di].strategic_cycle == 0:
                        self._adapt_dom(di, tick)
            if cfg.defender_tactical:
                if self._queue:
                    self._queue_step(tick)
                else:
                    for di in nd:
                        if tick % self.domains[di].tactical_cycle == 0:
                            self._tactical_dom(di, tick)
            if cfg.attacker_on and tick % cfg.attacker_cycle == 0:
                self._attacker(tick)
            self._record(tick)
            if self._roles:
                self._reconfigure(tick)
                self.impact += float(self._rec[self._def_idx].sum()) / max(len(self._def_idx), 1)
                if self._stages:
                    self._impact_step(tick)
                    out_v = float(self._nval[self._down].sum()) / self._nval_tot
                    self.svc_att += out_v
                    self.svc_def += float(self._nval[self.isolated & ~self._down].sum()) / self._nval_tot
                    if tick in MARK_TICKS:
                        self._marks[tick] = (float(self._dval[self._exfil].sum() / self._dval_tot),
                                             float(self.svc_att / tick), float(self._last_share))
                    if self.o.flag_value > 0 and out_v >= self.o.flag_value:
                        self.t_flag = tick      # the value flag: the estate's revenue is taken out
                        self.which_flag = 2
                        break
                if self._flag > 0 and self._last_share >= self._flag:
                    self.t_flag = tick          # the flag is captured: game over
                    self.which_flag = 1
                    break
        return self.rec

    def _record(self, tick: int):
        """Per-tick record. Keeps Engine4B's compromised count (the quantity Gate 0
        compares) and adds the trajectory measures: time spent compromised, the
        peak, the time of majority compromise, when each system and each
        management master first falls."""
        comp = self.state == COMPROMISED
        self.rec.tick.append(tick)
        self.rec.compromised.append(int((comp & self.est).sum()))
        share = float(comp[self._def_idx].sum()) / max(len(self._def_idx), 1)
        self._last_share = share
        if self._roles:
            c_ = self._cause
            c_[~comp & (self._inf_ref < 0)] = 0
            c_[comp & (c_ == 0)] = 1
        self.area += share
        if share > self.peak:
            self.peak = share
        if self.t_major < 0 and share > 0.5:
            self.t_major = tick
        cl = self.cluster_of[comp]
        frac = np.bincount(cl[cl >= 0], minlength=self.K) / self._csize
        new = (frac > 0.5) & (self.t_cluster < 0)
        if new.any():
            self.t_cluster[new] = tick
        for m in self.masters:
            if comp[m] and self.t_master[m] < 0:
                self.t_master[m] = tick
        if self._track_age:
            ct = self._comp_tick
            ct[~comp] = -1
            ct[comp & (ct < 0)] = tick

    # ---- start states and outcomes ---------------------------------------------
    def start(self, init: Optional[str]):
        """Clean start: only the hostile source is compromised. Collapsed start
        ('all'): every node of every cluster as well, masters excepted (E8)."""
        self.state[self.hostile] = COMPROMISED
        self.comp_ref[self.hostile] = 0
        bad = float(self.o.ext_bad) if self.o.route_sup else 0.0
        if self._ext and bad < 1.0:
            # an external party is compromised with a set chance, drawn each run
            for x_ in self._ext:
                if self._pay_rng.random() >= bad:
                    self.state[x_] = 0
                    self.comp_ref[x_] = -1
        # a service sited with a third party is compromised with the same
        # chance, and matters only to an attack that works through a supplier
        for x_ in self._outside:
            self.state[x_] = 0
            self.comp_ref[x_] = -1
        for x_ in self._outside_draw:
            if self._k_xchan and self._pay_rng.random() < bad:
                self.state[x_] = COMPROMISED
                self.comp_ref[x_] = 0
        cbad = float(self.o.cloud_bad) if self.o.route_sup else 0.0
        for x_ in self._outside_cloud:
            if self._k_xchan and cbad > 0 and self._pay_rng.random() < cbad:
                self.state[x_] = COMPROMISED
                self.comp_ref[x_] = 0
        if self._roles and self.o.edr_site and self._k_xchan and self._pay_rng.random() < bad:
            for ms in self._def_masters:
                for m_ in ms:
                    self.state[m_] = COMPROMISED
                    self.comp_ref[m_] = 0
                    self._cause[m_] = 2
        if init == "all":
            mset = set(self.masters)
            for j in np.flatnonzero(self.all_mask).tolist():
                if j not in mset:
                    self.state[j] = COMPROMISED
                    self.comp_ref[j] = 0
            self._comp_tick[self.state == COMPROMISED] = 0
        self.atk_reference = 0

    def _routes(self) -> dict:
        """Of the estate's nodes held at the end, the share taken by each route,
        and impact: the share of node-time spent reconfigured over the horizon
        (after the flag, every node then held counts as reconfigured)."""
        comp = self._compromised_mask()
        d = self._def_idx
        held = comp[d]
        n_held = max(int(held.sum()), 1)
        c_ = self._cause[d]
        T, H = max(len(self.rec.tick), 1), max(int(self.cfg.horizon), 1)
        imp = self.impact                       # observed reconfigured node-time only
        pen = (H - T) * float(held.mean()) if self.t_flag >= 0 else 0.0
        return dict(r1=float((held & (c_ == 1)).sum()) / n_held if held.any() else 0.0,
                    r2=float((held & (c_ == 2)).sum()) / n_held if held.any() else 0.0,
                    r3=float((held & (c_ == 3)).sum()) / n_held if held.any() else 0.0,
                    r0=float((held & (c_ == 4)).sum()) / n_held if held.any() else 0.0,
                    im=float(imp / H),                              # observed impact
                    pl=float(pen / H),                              # stipulated penalty after the flag
                    ex=float(self._excl[d].mean()),                 # share of nodes the defender is excluded from
                    al=int(self.n_alarms),
                    sv=float(T / H) if self.t_flag >= 0 else 1.0,   # share of the horizon the estate stood
                    ni=int(self.n_infected), nr=int(self.n_repelled),
                    hv=float(len(self._harvest)) / max(len(d), 1),      # share of nodes an infostealer harvested
                    wf=int(self.which_flag),                        # which flag fell: 1 volume, 2 value
                    fv=int(self.which_flag == 2),
                    sl=float(self.svc_att / T),                     # revenue lost to the attack, share per tick observed
                    sd=float(self.svc_def / T),                     # revenue lost to the defender's own isolation
                    dl=float(self._dval[self._exfil].sum() / self._dval_tot),   # share of data value exfiltrated
                    dn=float(self._down[d].mean()),                 # share of nodes out of service at the end
                    ne=int(self.n_esc), nw=int(self.n_esc_won),     # Privilege Escalation attempts, and won
                    qm=int(self.q_max),                             # largest backlog of waiting work
                    qw=float(self.q_wait / max(self.q_started, 1)),  # mean wait before work started, ticks
                    nh=int(self.n_hunt),                             # nodes found by hunting on an alarm
                    nc=int(sum(1 for m_ in self._cp_set if self.state[m_] == COMPROMISED)),  # Control Planes held at the end
                    nt=int(sum(1 for m_ in self._cp_set if self.t_master.get(m_, -1) >= 0)),  # Control Planes ever taken
                    cs=int(self.n_stolen),                           # service credentials stolen (node, service pairs)
                    cu=int(self.n_spent),                            # services taken with a stolen credential
                    cv=int(len(self._stolen)),                       # services whose credential is still held, valid, at the end
                    # damage at common observation times; -1 where the run had already stopped
                    **{f"{nm}{t_}": float(self._marks[t_][i_]) if t_ in self._marks else -1.0
                       for t_ in MARK_TICKS for i_, nm in enumerate(("d", "s", "c"))})

    def outcome(self) -> dict:
        """What one run contributes. 'estate' is the defender's own nodes."""
        comp = self._compromised_mask()
        T = max(len(self.rec.tick), 1)
        frac = np.array([comp[self.cluster_of == k].mean() for k in range(self.K)])
        tm = [t for t in self.t_master.values() if t >= 0]
        tc = self.t_cluster[self.t_cluster >= 0]
        return dict(
            f=float(comp[self._def_idx].mean()),              # final share, estate
            fa=float(comp[self.all_mask].mean()),             # final share, all systems
            ks=float((frac > 0.5).mean()),                    # share of systems collapsed
            pk=float(self.peak),                              # peak share, estate
            ar=float(self.area / T),                          # share of the run compromised
            tm=int(self.t_major),                             # time to majority (-1 never)
            tc=int(tc.min()) if tc.size else -1,              # first system to fall
            tk=int(min(tm)) if tm else -1,                    # first master captured
            nk=len(tm),                                       # masters ever captured
            mh=float(np.mean([self.state[m] == COMPROMISED    # share of masters held at the end
                              for m in self.masters])),
            fl=int(self.t_flag >= 0),                          # flag captured
            tf=int(self.t_flag),                               # tick of the flag (-1 never)
            **self._routes(),
            dh=float(np.mean([self._system_held(k) for k in range(self.K)])),   # systems with no automated defence
            ih=float(self._excl[self._def_idx].mean()),          # share of nodes the defender is excluded from
        )


def layout_4b(spec: ScenarioSpec, master: str, src: str) -> dict:
    """Describe a Paper 4B estate as a one-cluster 4C layout."""
    nodes = [n.id for n in spec.nodes if n.id not in (master, src)]
    return dict(clusters=[nodes], masters=[[master]], source=src, gamma=0)


# ============================================================================
# The knobs (see Paper_4C_Knob_Register). Defaults are the neutral point.
# ============================================================================
@dataclass(frozen=True)
class Knobs:
    """One configuration. All values are starting values, declared in the run
    record; none was tuned toward a hypothesis. Where a default reproduces the
    Paper 4B engine's behaviour, the comment says so."""
    topology: str = "chain"          # chain | star | mesh (the backbone inside each system)
    K: int = 4                       # (4B estates only; the 4C estate is built from the zone dials below)
    m: int = 25                      # nodes per system (masters excluded)
    # ---- node layer
    ext_share: float = 0.05          # entry by Interface, phishing: share of endpoints the hostile source reaches
    supplied_x: float = 0.25         # share of nodes with no native Execution Pathway
    supplied_a: float = 0.25         # share of nodes with no native Authority
    iface_closed: float = 0.0        # share of nodes whose interface is closed to Connections (4B: 0)
    x_rate: float = 0.55             # admission ease, Execution side (4B: 0.55)
    a_rate: float = 0.55             # admission ease, Authority side (4B: 0.55)
    rate_var: float = 0.10           # variation of admission ease between nodes (4B: 0.1)
    visibility: float = 1.0          # Node visibility: share of nodes on which a compromise is detected (4B: 1)
    blind_delay: int = 9999          # ticks before an unseen node's compromise is found (9999 = never, 4B)
    # ---- systematic layer
    conn: float = -1.0               # mesh: mean degree; chain, star: extra mean degree. -1 = default
    chan: float = 0.15               # share of nodes receiving an extra within-system Channel
    g: float = 0.05                  # control-plane exposure: share with a connection up to a master
    coverage: float = 1.0            # Control Coverage: share of nodes the automated control reaches (4B: 1)
    masters: int = 2                 # master controllers per zone: endpoint detection, then Active Directory
                                     # (fixed; 4B: 1)
    dns: int = 1                     # one DNS service for the whole estate: a Channel that selects the supplier
                                     # of the other Channels (0 = none)
    zone_conn: float = 1.0           # share of the possible connections inside a zone that exist, beyond the
                                     # backbone (1 = everything in a zone reaches everything else in it)
    ad_reach: float = 1.0            # share of a zone's nodes its Active Directory controller reaches
    managed: float = 1.0             # of the nodes that carry the control, the share managed by endpoint detection
    hand_delay: int = 24             # ticks before a signature reaches a control that is updated by hand
    reconf_time: int = 2             # ticks from capturing a master controller to reconfiguring its nodes
    ctl_link: int = 2                # controllers in communication: 0 none, 1 neighbouring zones, 2 all
    repl_delay: int = 8              # ticks for a captured controller's authority to reach a linked controller
    n_chan: int = 3                  # software-delivery channels
    chan_cov: float = 0.8            # share of a served zone's nodes each delivery channel reaches
    chan_span: float = 1.0           # share of the other zones each delivery channel also serves
    dmz: int = 1                     # zones outside every delivery channel (a DMZ)
    stage_time: int = 0              # staged rollout: ticks over which a channel's delivery is spread (0 = at once)
    ext_chan: float = 0.2            # entry by Execution Pathway: share of nodes served by a compromised external supplier
    ext_ctl: float = 0.05             # entry by Authority: share of nodes a compromised external trusted party directs
    # ---- the four zones (v0.11): endpoints, servers, cloud, external
    size: int = 100                  # nodes in the estate (endpoints and servers; external parties are extra)
    server_share: float = 0.2        # share of the estate that is servers; the rest are endpoints
    remote_share: float = 0.2        # share of endpoints that are remote (outside the network, not connected
                                     # to one another)
    cloud_share: float = 0.3         # share of servers that are in the cloud
    seg_ep: int = 2                  # network segments the internal endpoints are cut into
    seg_sv: int = 2                  # network segments the on-premises servers are cut into
    ep_conn: float = 1.0             # share of the possible connections between endpoints of one segment that exist
    ep_sv: float = 0.3               # connections from an endpoint segment to a server segment, per node
    cloud_link: float = 0.3          # connections from each endpoint or server group to the cloud, per node
    vpn: float = 0.15                # connections from the remote endpoints to each server segment, per node
    ext_exploit: float = 0.2         # entry by Interface, exploit: share of servers with an outward-facing service
    n_ext: int = 4                   # external parties the estate trusts
    ext_total: float = 0.4           # share of the estate the external parties reach between them
    ext_auth: float = 0.0            # share of external parties that hold Authority (the rest supply a Channel)
    ceil_deliv: float = 60.0         # ceiling of a software-delivery Channel: the most authority it can deliver
    ceil_edr: float = 80.0           # ceiling of the endpoint detection Channel
    ceil_ext: float = 60.0           # ceiling of an external supplier's Channel
    chan_verify: float = 0.5         # share of delivery Channels that verify their supplier (DNS cannot redirect them)
    route_cred: int = 1              # ablation switch: the credential route to a Control Plane
    route_sup: int = 1               # ablation switch: the supplier route (external parties, third-party services)
    route_lat: int = 1               # ablation switch: the lateral route (node to node)
    # ---- v0.14: the ATT&CK stages
    stages: int = 1                  # Authority per action, escalation above a Channel's ceiling (0 = v0.13)
    auth_cred: float = 70.0          # Authority needed for Credential Access
    auth_destroy: float = 50.0       # v0.16 only: Authority a destructive payload needed; unused under the stage rule
    auth_reconf: float = 100.0       # Authority needed to reconfigure a node (fixed, not walked)
    route_esc: int = 1               # ablation switch: Privilege Escalation attempts
    c2_share: float = 0.8            # Command and Control: share of nodes with a route out of the estate
    objective: str = "kind"          # does the payload exfiltrate: steal | both (yes), destroy (no), kind (the kind's default)
    exfil_p: float = 0.5             # chance an Exfiltration attempt succeeds
    val_sv: float = 10.0             # node value (revenue per tick) of a server; an endpoint is 1
    dval_sv: float = 20.0            # data value of a server; an ordinary endpoint is 1
    dval_exc: float = 10.0           # data value of an exceptional endpoint
    exc_share: float = 0.02          # share of endpoints that are exceptional (drawn from those holding a
                                     # Control Plane credential)
    flag_value: float = 0.8          # the second flag: this share of node value taken out (0 = none)
    queue: int = 1                   # the team is one queue of jobs with durations (0 = v0.13)
    t_clean: int = 1                 # ticks to clean a node (isolated meanwhile)
    t_cut: int = 1                   # ticks to cut a relation
    queue_order: str = "value"       # order of the team's work: value | fifo | degree
    # ---- v0.15: sensitivity switches, not walked (the defaults are the model's rules)
    auth_conn: float = 0.0           # Authority held after winning a node's own checks over a Connection (rule: a foothold)
    exfil_esc: float = 0.9           # chance Exfiltration succeeds after escalation (only the network control remains)
    stage_down: int = 1              # rule: a won escalation takes the node out of service until rebuilt
    retry: int = 1                   # rule: each new payload from the source retries escalation on the attacker's footholds
    hunt: int = 1                    # rule: an alarm investigated sends the team hunting the same payload on every agent
    sig_block: float = 0.99          # a known signature is matched and blocked by every agent with this reliability;
                                     # an unknown payload faces Defender Capability as a probability, and the two add
    # ---- v0.21 (Paul, 18 October): stolen service credentials and the campaign
    steal_p: float = 0.5             # chance a stealer landing on a credential-holding node takes that service's credential
    rotate: int = 1                  # 0 never; 1 a cleaned or rebuilt node's stolen credentials are rotated;
                                     # 2 every stolen credential of each service that node held is rotated
    cred_ttl: int = 9999             # ticks a stolen credential stays valid on its own (9999 = until rotated)
    handoff: int = 20                # campaign: ticks of stealer payloads before the intrusion payloads begin
    # ---- exposure by count (the drill): overrides g when cred_total >= 0
    cred_total: int = -1             # exposed privileged credentials in the whole estate, an absolute count (no rounding)
    cred_only: str = "all"           # which services may be exposed: all, or a comma list of ad, mdm, hv, hvc, edr, dns
    down_inert: int = 0              # 1 = a node taken out cannot be used by the attacker
    edr_site: int = 0                # endpoint detection sited inside the estate (0) or with a third party (1)
    dns_site: int = 0                # DNS sited inside the estate (0) or with a third party (1)
    cloud_bad: float = 0.0           # chance the cloud provider's hypervisor is compromised at the start of a run
    ext_bad: float = 0.5             # chance that an external party is compromised at the start of a run
    kind: str = "mixed"              # attack kind: malware | implant | intrusion | stealer | campaign | mixed
    fixed_clock: float = 0.0         # share of dormant attacks whose payloads all trigger on one fixed tick
    payload: int = 1                 # infected is not captured: payloads trigger after a delay (4B: 0)
    payload_delay: int = 1           # the usual delay before a payload triggers, ticks
    dormant_share: float = 0.1       # share of attacks whose payload carries the long timer
    dormant_delay: int = 48          # the long timer, ticks
    cap_spread: float = 0.5          # each attack's capability varies by this fraction around Attacker Capability
    node_reconf: int = 4             # ticks the attacker must hold a node before it can act on its Authority there: take a credential, exfiltrate, take the node out, reconfigure it
    flag: float = 0.8                # the game is over when this share of the estate is compromised (4B: no flag)
    rollout: int = 0                 # largest rollout delay on directing planes, ticks (4B: 0)
    # ---- systemic layer
    concentration: float = 0.15      # connections between each pair of zones, per node
    dependency: float = 0.0         # cross-system Channel receivers per ordered pair, per node
    ext_trust: float = 0.0          # cross-system directing-plane members per ordered pair, per node
    ext_conf: float = 0.0            # share of supplied-Authority nodes conferred from another system
    ext_clock: float = 1.0           # other systems' defenders' cadence relative to the defender's
    # ---- operators
    fanout: float = 0.25             # pool size = redundancy / fanout
    inequality: float = 1.0          # Zipf exponent over the supplier pool (0 = even)
    redundancy: int = 2              # suppliers per supplied receiver (1 = every supply is a Cut)
    theta: str = "any"               # dependency threshold: any | majority | all
    # ---- time
    tac_cadence: int = 5             # 4B clean-up cadence; superseded by the queue (work is taken every tick), not walked
    block_delay: int = 2             # lag before a block lands (4B: 2)
    c_s: int = 20                    # structural tempo: ticks between adaptation turns (4B: 20)
    obs_interval: int = 1            # defender refreshes its picture every this many ticks (4B: 1)
    detect_latency: int = 0          # ticks before a new compromise can be observed (4B: 0)
    # ---- adaptation and the defender
    dose: float = 0.0                # share of its inbound relations a defender may cut per turn
    tac_budget: float = 5.0          # responders in the team per 40 nodes: each does one job at a time (4B: clean-ups per turn)
    success: float = 0.8             # fixed chance a defender action works; used by the 4B and
                                     # cut-off rules only, not walked
    def_cap: float = 80.0            # Defence Capability, 1 to 100
    cap_rule: str = "ratio"          # how relative capability sets reliability: ratio | cutoff | fixed
    manual_scope: int = 1            # the team leaves to the automated track what it can fix; an alarm is always the team's
    auto_clean: int = 1              # automated track: a landed block also cleans (4B: 0)
    rebuild_time: int = 5            # ticks to rebuild a node that was reconfigured or taken out, or to restore a console or DNS
    priority: int = 1                # v0.13 manual order; superseded by queue_order, not walked
    manual_delay: int = 2            # ticks a responder takes to investigate an alarm or a reported compromise (the golden hour)
    lockout_delay: int = 9999          # manual response delay in a system whose identity plane is held; 9999 = locked out
    master_rebuild: int = 9999         # ticks to rebuild a captured master; 9999 = never (4B: -1, handled as a node)
    retool_fix: int = 1              # attacker re-tool rule ignores nodes without the control (4B: 0); a rule, not walked
    # ---- attacker
    atk_budget: int = 1              # re-establishments and re-openings per attacker action (E8: 1)
    atk_cap: float = 20.0            # Attacker Capability, 1 to 100 (20 gives the 4B admission rate)
    retool: int = 20                 # ticks between new references from the source (4B: tied to c_s)
    cap_drift: float = 0.0           # security drift: capability gained per 100 ticks (4B: 0)
    # ---- measurement settings
    horizon: int = 600
    wiring_seed: int = 6001

    def conn_value(self) -> float:
        if self.conn >= 0:
            return self.conn
        return 6.0 if self.topology == "mesh" else 0.0


def make_cfg(kn: Knobs, spread: int, recovery: int, seed: int) -> Config:
    """cfg_e8 with the knobs that are Config fields set from kn."""
    c = cfg_e8(spread, recovery, kn.c_s, kn.horizon, seed, adaptation=kn.dose > 0)
    c.tactical_cycle = int(kn.tac_cadence)
    c.block_delay = int(kn.block_delay)
    c.def_success_prob = float(kn.success)
    c.atk_budget = int(kn.atk_budget)
    return c


def make_opts(kn: Knobs) -> Opts:
    return Opts(theta=kn.theta, ext_clock=kn.ext_clock, dose=kn.dose, tac_per_40=kn.tac_budget,
                retool=kn.retool, atk_cap=float(kn.atk_cap), def_cap=float(kn.def_cap),
                cap_rule=kn.cap_rule, manual_scope=bool(kn.manual_scope),
                obs_interval=kn.obs_interval,
                detect_latency=kn.detect_latency, cap_drift=kn.cap_drift,
                blind_delay=kn.blind_delay, auto_clean=bool(kn.auto_clean),
                rebuild_time=int(kn.rebuild_time), priority=bool(kn.priority),
                manual_delay=int(kn.manual_delay), master_rebuild=int(kn.master_rebuild),
                lockout_delay=int(kn.lockout_delay), flag=float(kn.flag),
                reconf_time=int(kn.reconf_time), repl_delay=int(kn.repl_delay),
                ctl_link=int(kn.ctl_link), stage_time=int(kn.stage_time),
                hand_delay=int(kn.hand_delay), payload=bool(kn.payload),
                payload_delay=int(kn.payload_delay), dormant_share=float(kn.dormant_share),
                dormant_delay=int(kn.dormant_delay), cap_spread=float(kn.cap_spread),
                node_reconf=int(kn.node_reconf), kind=str(kn.kind),
                fixed_clock=float(kn.fixed_clock), ext_bad=float(kn.ext_bad), cloud_bad=float(kn.cloud_bad),
                edr_site=int(kn.edr_site), dns_site=int(kn.dns_site),
                ceil_deliv=float(kn.ceil_deliv), ceil_edr=float(kn.ceil_edr), ceil_ext=float(kn.ceil_ext),
                route_cred=bool(kn.route_cred), route_sup=bool(kn.route_sup), route_lat=bool(kn.route_lat),
                stages=bool(kn.stages), auth_cred=float(kn.auth_cred), auth_destroy=float(kn.auth_destroy),
                auth_reconf=float(kn.auth_reconf), route_esc=bool(kn.route_esc),
                c2=bool(kn.c2_share < 1.0), objective=str(kn.objective), exfil_p=float(kn.exfil_p),
                val_sv=float(kn.val_sv), dval_sv=float(kn.dval_sv), dval_exc=float(kn.dval_exc),
                flag_value=float(kn.flag_value), queue=bool(kn.queue), t_clean=int(kn.t_clean),
                t_cut=int(kn.t_cut), queue_order=str(kn.queue_order),
                auth_conn=float(kn.auth_conn), down_inert=bool(kn.down_inert),
                exfil_esc=float(kn.exfil_esc), stage_down=bool(kn.stage_down),
                retry=bool(kn.retry), hunt=bool(kn.hunt), sig_block=float(kn.sig_block),
                steal_p=float(kn.steal_p), rotate=int(kn.rotate), cred_ttl=int(kn.cred_ttl),
                handoff=int(kn.handoff), retool_fix=bool(kn.retool_fix))


# ============================================================================
# Structure generator
# ============================================================================
def _wrng(seed: int, tag: int) -> np.random.Generator:
    """One generator per wiring component, so changing one knob does not
    reshuffle the wiring that knob does not touch."""
    return np.random.default_rng([int(seed), int(tag)])


def _cnt(share: float, m: int) -> int:
    if share <= 0:
        return 0
    return max(1, int(round(share * m)))


def _zipf_pick(rng, pool: List[str], k: int, s: float, exclude: str) -> List[str]:
    elig = [p for p in pool if p != exclude]
    if not elig or k <= 0:
        return []
    k = min(k, len(elig))
    w = np.array([(pool.index(p) + 1.0) ** (-float(s)) for p in elig])
    return [str(x) for x in rng.choice(elig, size=k, replace=False, p=w / w.sum())]


def generate(kn: Knobs, gamma: int = 0):
    """Build the estate of Paper_4C_Structure_and_Collapse: four zones.

      endpoints  user machines. The internal ones are cut into seg_ep network
                 segments; the remote ones are one group, not connected to one
                 another
      servers    on-premises servers, cut into seg_sv segments, every server in
                 a segment reaching every other
      cloud      servers hosted elsewhere, on someone else's hypervisor
      external   third parties. Never connected to one another; each reaches
                 back into the estate by a Channel or with Authority

    Services. Master control planes (reconfiguration tools): Active Directory,
    one controller per internal endpoint segment and per on-premises server
    segment; a hypervisor over the on-premises servers and another over the
    cloud servers; device management over the endpoints. Channels (update
    mechanisms): endpoint detection, one console per group, which also carries
    the defence; software delivery; DNS, over the other Channels. A controller,
    console or DNS has no Connections: it is taken through its privileged
    credential. gamma is accepted for compatibility; the estate is one
    governance."""
    S, r = kn.wiring_seed, int(kn.redundancy)
    N = max(4, int(kn.size))
    n_sv = min(N, max(0, int(round(kn.server_share * N))))
    n_ep = N - n_sv
    n_rem = min(n_ep, max(0, int(round(kn.remote_share * n_ep))))
    n_int = n_ep - n_rem
    n_cl = min(n_sv, max(0, int(round(kn.cloud_share * n_sv))))
    n_on = n_sv - n_cl

    def cut(n, parts, tag):
        parts = max(1, min(int(parts), n)) if n else 0
        return [[f"{tag}{p}n{i}" for i in range(n // parts + (1 if p < n % parts else 0))]
                for p in range(parts)]

    groups = ([("ep", c) for c in cut(n_int, kn.seg_ep, "e")]
              + ([("rem", [f"rn{i}" for i in range(n_rem)])] if n_rem else [])
              + [("sv", c) for c in cut(n_on, kn.seg_sv, "s")]
              + ([("cloud", [f"cn{i}" for i in range(n_cl)])] if n_cl else []))
    types = [g[0] for g in groups]
    cl = [g[1] for g in groups]
    K = len(cl)
    idx_of = lambda ty: [k for k in range(K) if types[k] == ty]
    rels: List[Relation] = []
    seen: Set[tuple] = set()
    tally = dict(within_conn=0, cross_conn=0, admin=0, entry=0)
    directed: List[tuple] = []
    pools: Dict[str, List[str]] = {}

    def add_conn(a, b, kind):
        key = ("c",) + tuple(sorted((a, b)))
        if a == b or key in seen:
            return False
        seen.add(key)
        rels.append(Relation(a, b, Condition.INTERFACE, CONNECTION))
        tally[kind] += 1
        return True

    def add_dir(cell, rc, sup, rcv, group=None):
        key = (rc.value, sup, rcv)
        if sup == rcv or key in seen:
            return False
        seen.add(key)
        cond = Condition.EXECUTION_PATHWAY if rc == CHANNEL else Condition.AUTHORITY
        rels.append(Relation(sup, rcv, cond, rc, conferral=(rc != CHANNEL), group=group))
        if cell is not None:
            directed.append((cell, sup, rcv))
        return True

    def pool(cell, k, tag):
        key = f"{cell}:{k}"
        if key not in pools:
            m_ = len(cl[k])
            ps = min(m_, max(r + 1, int(round(r / max(kn.fanout, 1e-9)))))
            pools[key] = [str(x) for x in _wrng(S, tag * 100 + k).choice(cl[k], size=ps, replace=False)]
        return pools[key]

    def pick(rng_, items, share):
        n_ = min(len(items), max(0, int(round(share * len(items)))))
        return [str(x) for x in rng_.choice(items, size=n_, replace=False)] if n_ else []

    # ---- node layer -----------------------------------------------------------
    no_x, no_a, closed, unseen = set(), set(), set(), set()
    for k in range(K):
        for share, tag, bag in ((kn.supplied_x, 1100, no_x), (kn.supplied_a, 1200, no_a),
                                (kn.iface_closed, 1300, closed), (1.0 - kn.visibility, 1400, unseen)):
            bag.update(pick(_wrng(S, tag + k), cl[k], share))

    # ---- connections inside a group -------------------------------------------
    for k in range(K):
        c, ty = cl[k], types[k]
        dens = 0.0 if ty == "rem" else (kn.ep_conn if ty == "ep" else kn.zone_conn)
        if dens > 0 and len(c) > 1:
            pairs = [(i, j) for i in range(len(c)) for j in range(i + 1, len(c))]
            order_ = _wrng(S, 2500 + k).permutation(len(pairs))
            for q in order_[:int(round(dens * len(pairs)))]:
                add_conn(c[pairs[int(q)][0]], c[pairs[int(q)][1]], "within_conn")
        # peer supply inside the group, as before: a node with no native
        # Execution Pathway is supplied one, a node with no native Authority is
        # conferred it
        rngc = _wrng(S, 3000 + k)
        extra_rcv = pick(rngc, c, kn.chan) if len(c) > 1 else []
        for rcv in [x for x in c if x in no_x] + [x for x in extra_rcv if x not in no_x]:
            for sup in _zipf_pick(rngc, pool("chan", k, 31), r, kn.inequality, rcv):
                add_dir("chan", CHANNEL, sup, rcv)
        rnga = _wrng(S, 4000 + k)
        for rcv in [x for x in c if x in no_a]:
            for sup in _zipf_pick(rnga, pool("conf", k, 41), r, kn.inequality, rcv):
                add_dir("conf", CONFERRING, sup, rcv, group=f"idp-{sup}")

    # ---- connections between groups -------------------------------------------
    def link(a, b, dens, tag):
        if dens <= 0 or not cl[a] or not cl[b]:
            return
        rng_ = _wrng(S, 5000 + tag)
        want, tries = _cnt(dens, min(len(cl[a]), len(cl[b]))), 0
        while want > 0 and tries < 2000:
            tries += 1
            if add_conn(cl[a][int(rng_.integers(0, len(cl[a])))],
                        cl[b][int(rng_.integers(0, len(cl[b])))], "cross_conn"):
                want -= 1

    for a in range(K):
        for b in range(a + 1, K):
            ta, tb = sorted((types[a], types[b]))
            pair = (ta, tb)
            if pair in (("ep", "ep"), ("sv", "sv")):
                dens = kn.concentration          # between segments of the same kind
            elif pair == ("ep", "sv"):
                dens = kn.ep_sv
            elif "cloud" in pair:
                dens = kn.cloud_link
            elif pair == ("rem", "sv"):
                dens = kn.vpn
            else:
                dens = 0.0                       # remote endpoints do not reach internal endpoints
            link(a, b, dens, a * 64 + b)

    # ---- services ----------------------------------------------------------------
    everyone = [x for c in cl for x in c]
    endpoints = [x for k in range(K) if types[k] in ("ep", "rem") for x in cl[k]]
    onprem = [x for k in idx_of("sv") for x in cl[k]]
    cloud = [x for k in idx_of("cloud") for x in cl[k]]
    servers = onprem + cloud
    masters = [[f"c{k}m0"] + ([f"c{k}m1"] if types[k] in ("ep", "sv") else []) for k in range(K)]
    covered, control_only, cred = [], [], {}
    joined = [k for k in range(K) if types[k] in ("ep", "sv")]
    tot = _cnt(kn.g, N)

    def holders(rng_, items, n_):
        n_ = min(len(items), max(0, int(n_)))
        return [str(x) for x in rng_.choice(items, size=n_, replace=False)] if n_ else []

    for k in range(K):
        c = cl[k]
        ctl = c if kn.coverage >= 1 else sorted(pick(_wrng(S, 8500 + k), c, kn.coverage))
        man = list(ctl) if kn.managed >= 1 else sorted(pick(_wrng(S, 8600 + k), ctl, kn.managed))
        covered.append(list(man))
        control_only.append([x for x in ctl if x not in set(man)])
        for x in man:
            add_dir(None, DIRECTING, masters[k][0], x, group=f"edr{k}")
        # credential holders: a share g of the whole estate for each kind of
        # service, however the estate is cut up, spread evenly over the groups
        mine = tot // K + (1 if k < tot % K else 0)
        cred[masters[k][0]] = holders(_wrng(S, 8000 + 10 * k), c, mine)
        if len(masters[k]) > 1:
            for x in (c if kn.ad_reach >= 1 else pick(_wrng(S, 8700 + k), c, kn.ad_reach)):
                add_dir(None, DIRECTING, masters[k][1], x, group=f"ad{k}")
            j_ = joined.index(k)
            mine_ad = tot // len(joined) + (1 if j_ < tot % len(joined) else 0)
            cred[masters[k][1]] = holders(_wrng(S, 8001 + 10 * k), c, mine_ad)
    for v in cred.values():
        tally["admin"] += len(v)
    # masters over a whole kind of node: a hypervisor over the on-premises
    # servers, another (the provider's) over the cloud servers, and device
    # management over the endpoints
    estate_masters, authority = [], {}
    for mid, reach, over, tag in (("hv", onprem, idx_of("sv"), 8910), ("hvc", cloud, idx_of("cloud"), 8920),
                                  ("mdm", endpoints, idx_of("ep") + idx_of("rem"), 8930)):
        if not reach:
            continue
        estate_masters.append(mid)
        authority[mid] = list(over)
        for x in reach:
            add_dir(None, DIRECTING, mid, x, group=mid)
        cred[mid] = holders(_wrng(S, tag), everyone, tot)
        tally["admin"] += len(cred[mid])
    dns_id = "dns" if int(kn.dns) > 0 else None
    if dns_id:
        cred[dns_id] = holders(_wrng(S, 8900), everyone, tot)
        tally["admin"] += len(cred[dns_id])
    if int(kn.cred_total) >= 0:
        # exposure by count: exactly cred_total credentials in the estate, each
        # for a service drawn at random among those allowed, on a node drawn
        # from that service's own population. Scales up from zero; no rounding
        allowed = set(x.strip() for x in str(kn.cred_only).split(",")) if kn.cred_only != "all" else None
        svc = []
        for k in range(K):
            svc.append(("edr", masters[k][0], cl[k]))
            if len(masters[k]) > 1:
                svc.append(("ad", masters[k][1], cl[k]))
        for mid in estate_masters:
            svc.append((mid, mid, everyone))
        if dns_id:
            svc.append(("dns", dns_id, everyone))
        if allowed is not None:
            svc = [t for t in svc if t[0] in allowed]
        for key in cred:
            cred[key] = []
        rngk = _wrng(S, 8950)
        placed = 0
        while placed < int(kn.cred_total) and svc:
            tag, mid, popn = svc[int(rngk.integers(0, len(svc)))]
            free = [x for x in popn if x not in cred[mid]]
            if not free:
                svc = [t for t in svc if t[1] != mid]
                continue
            cred[mid].append(str(rngk.choice(free)))
            placed += 1
        tally["admin"] = sum(len(v) for v in cred.values())
    # software delivery: each channel has a server (an on-premises server, or a
    # cloud one if there are none), and serves chan_cov of the nodes of
    # chan_span of the groups, in a fixed delivery order
    channels, ext_nodes = [], []

    def _served(rng_, ks, share, exclude=None):
        out = []
        for z in ks:
            out += pick(rng_, [x for x in cl[z] if x != exclude], share)
        order_ = rng_.permutation(len(out))
        den = max(len(out) - 1, 1)
        return [(out[int(q)], r_ / den) for r_, q in enumerate(order_)]

    hosts = onprem or cloud
    for i in range(int(kn.n_chan) if hosts else 0):
        rngh = _wrng(S, 22000 + i)
        server = str(rngh.choice(hosts))
        n_g = max(1, int(round(kn.chan_span * K)))
        ks = [int(z) for z in rngh.choice(K, size=min(n_g, K), replace=False)]
        channels.append(dict(server=server, kind="chan", external=False,
                             verified=i < int(np.floor(kn.chan_verify * int(kn.n_chan) + 0.5)),
                             served=_served(rngh, ks, kn.chan_cov, exclude=server)))
    # the external zone: n_ext third parties sharing a total reach of ext_total
    # of the estate. A share ext_auth of them hold Authority; the rest supply a
    # Channel. Whether each is compromised is drawn at the start of every run
    n_x = max(0, int(kn.n_ext))
    if n_x and kn.ext_total > 0:
        rngx = _wrng(S, 23000)
        n_auth = int(np.floor(kn.ext_auth * n_x + 0.5))
        auth_ix = set(int(q) for q in rngx.permutation(n_x)[:n_auth])
        # the parties share one set of nodes, dealt out between them, so the
        # total reach is exactly ext_total of the estate whatever their number
        pooled = pick(_wrng(S, 23100), everyone, kn.ext_total)
        for i in range(n_x):
            xid = f"x{i}"
            ext_nodes.append(xid)
            reach = pooled[i::n_x]
            order_ = _wrng(S, 23500 + i).permutation(len(reach))
            den = max(len(reach) - 1, 1)
            channels.append(dict(server=xid, kind="ctl" if i in auth_ix else "chan", external=True,
                                 served=[(reach[int(q)], r_ / den) for r_, q in enumerate(order_)]))
    # ---- entry by Interface: phishing reaches endpoints, exploits reach servers
    entries = []
    for items, share, tag in ((endpoints, kn.ext_share, 9000), (servers, kn.ext_exploit, 9001)):
        ok = [x for x in items if x not in closed]
        entries += holders(_wrng(S, tag), ok, _cnt(share, len(items)) if items else 0)
    for e in entries:
        add_conn("src", e, "entry")

    # Command and Control: the nodes with a route out of the estate
    egress = sorted(pick(_wrng(S, 9100), everyone, kn.c2_share)) if kn.c2_share < 1.0 else list(everyone)
    # exceptional endpoints (high data value): drawn first from the endpoints
    # that hold a Control Plane credential, such as an administrator's laptop
    ep_set = set(endpoints)
    cp_ids = [ms[1] for ms in masters if len(ms) > 1] + estate_masters
    cands = []
    for mid in cp_ids:
        cands += [x for x in cred.get(mid, []) if x in ep_set and x not in cands]
    n_exc = min(len(endpoints), _cnt(kn.exc_share, len(endpoints)))
    rest = [x for x in endpoints if x not in set(cands)]
    if n_exc > len(cands) and rest:
        cands += [str(x) for x in _wrng(S, 9200).permutation(rest)]
    exceptional = cands[:n_exc]
    gov = [Governance("estate", True), Governance("hostile", False)]
    nodes = [Node(id=x, governance="estate", interface=True, execution_pathway=x not in no_x,
                  authority=x not in no_a, visible=x not in unseen) for x in everyone]
    dns_out = bool(dns_id) and int(kn.dns_site) > 0
    # governed by a third party: the cloud provider's hypervisor always, and
    # DNS and the endpoint detection consoles when they are sited outside
    outside_draw = [dns_id] if dns_out else []
    outside_cloud = ["hvc"] if "hvc" in estate_masters else []
    consoles_out = [ms[0] for ms in masters] if int(kn.edr_site) > 0 else []
    outside = outside_draw + outside_cloud + consoles_out
    for x_ in ["src"] + ext_nodes + outside:
        nodes.append(Node(id=x_, governance="hostile", interface=True,
                          execution_pathway=True, authority=True, visible=False))
    for mid in [m_ for ms in masters for m_ in ms] + estate_masters + ([dns_id] if dns_id else []):
        if mid in outside:
            continue
        nodes.append(Node(id=mid, governance="estate", interface=True,
                          execution_pathway=True, authority=True, visible=True))
    spec = ScenarioSpec(id=f"4c-zones", description="Paper 4C", governance=gov, nodes=nodes,
                        relations=rels, seed=kn.wiring_seed, deterministic=False)
    spec.rates = RateSpec(execution_rate=float(kn.x_rate), authority_rate=float(kn.a_rate),
                          control_variance=float(kn.rate_var))
    problems = spec.validate()
    if problems:
        raise ValueError("generated spec invalid: " + "; ".join(problems))
    zones_out = [list(c_) for c_ in cl]
    if dns_id and not dns_out:
        zones_out[0] = zones_out[0] + [dns_id]
    layout = dict(clusters=zones_out, masters=masters, source="src", gamma=0, roles=True,
                  outside=outside, outside_draw=outside_draw, outside_cloud=outside_cloud,
                  covered=covered, closed=sorted(closed), control_only=control_only,
                  cred=cred, dns=dns_id, channels=channels, ext_nodes=ext_nodes,
                  estate_masters=estate_masters, authority=authority, types=types,
                  egress=egress, exceptional=exceptional)
    built = dict(tally=tally, directed=directed, pools=pools, no_x=sorted(no_x), no_a=sorted(no_a),
                 entries=entries, n_relations=len(rels), closed=sorted(closed), unseen=sorted(unseen),
                 n_covered=sum(len(c_) for c_ in covered), n=len(everyone), types=types,
                 sizes=[len(c_) for c_ in cl], n_endpoints=len(endpoints), n_servers=len(servers),
                 n_cloud=len(cloud), n_remote=n_rem, n_external=len(ext_nodes),
                 ext_reach=sum(len(ch["served"]) for ch in channels if ch["external"]))
    return spec, layout, built


# ---------------------------------------------------------------------------
# Realised structure (measured, never assumed from the knob)
# ---------------------------------------------------------------------------
def _gini(v: List[int]) -> float:
    a = np.sort(np.asarray(v, dtype=float))
    if a.size == 0 or a.sum() == 0:
        return 0.0
    n = a.size
    return float((2 * np.arange(1, n + 1) - n - 1).dot(a) / (n * a.sum()))


def realised(kn: Knobs, built: dict) -> Dict[str, float]:
    n = max(built["n"], 1)
    t = built["tally"]
    d = built["directed"]
    out: Dict[str, float] = dict(
        n=n, groups=len(built["sizes"]),
        endpoint_share=built["n_endpoints"] / n, server_share=built["n_servers"] / n,
        cloud_share_of_estate=built["n_cloud"] / n, remote_share_of_estate=built["n_remote"] / n,
        external_parties=built["n_external"], external_reach=built["ext_reach"] / n,
        entry_share=t["entry"] / n,
        conn_degree_within=2.0 * t["within_conn"] / n,
        cross_conn_per_node=t["cross_conn"] / n,
        credential_holdings_per_node=t["admin"] / n,
        chan_recv_share=len({rv for c, _, rv in d if c == "chan"}) / n,
        supplied_x_share=len(built["no_x"]) / n,
        supplied_a_share=len(built["no_a"]) / n,
        closed_share=len(built["closed"]) / n,
        unseen_share=len(built["unseen"]) / n,
        coverage=built["n_covered"] / n,
        n_relations=built["n_relations"],
        n_directed_supply=len(d),
    )
    outdeg: Dict[tuple, int] = {}
    for key, members in built["pools"].items():
        cell = key.split(":")[0]
        for p in members:
            outdeg.setdefault((cell, p), 0)
    for c, s, _ in d:
        outdeg[(c, s)] = outdeg.get((c, s), 0) + 1
    used = [v for v in outdeg.values() if v > 0]
    out["fanout_mean"] = float(np.mean(used)) if used else 0.0
    out["fanout_max"] = float(max(used)) if used else 0.0
    out["supplier_gini"] = _gini(list(outdeg.values()))
    per_rcv: Dict[tuple, int] = {}
    for c, _, rv in d:
        cls = "channel" if c in ("chan", "dep") else ("conferring" if c in ("conf", "xconf")
                                                      else "directing")
        per_rcv[(cls, rv)] = per_rcv.get((cls, rv), 0) + 1
    single = sum(1 for v in per_rcv.values() if v == 1)
    out["single_supplier_share"] = single / len(per_rcv) if per_rcv else 0.0
    deficits = [("channel", x) for x in built["no_x"]] + [("conferring", x) for x in built["no_a"]]
    out["cut_share_of_supplied_corners"] = (
        sum(1 for k_ in deficits if per_rcv.get(k_, 0) == 1) / len(deficits)) if deficits else 0.0
    return out


# ============================================================================
# The register in code: every walked knob, its layer, who moves it, its ladder
# ============================================================================
# who: L = defender lever, A = attacker, G = given
# Ladders (v0.8). The sweep studies value ranges and nothing else: no level is
# claimed to be normal. A knob that is a share runs evenly across its whole range,
# ends included (0, 20, 40, 60, 80, 100 per cent). Two shares whose effect is known
# to sit below 20 per cent (the external interface share and the control-plane
# exposure) also carry 5 and 10 per cent, and the adaptation dose carries 1, 5 and
# 10 per cent. A knob that is a time runs by doubling between a declared minimum
# and maximum; a count runs evenly.
_SH = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
REGISTER = dict(
    ext_share=("node", "L", "Entry by Interface, phishing: share of endpoints reached", [0.0, 0.05, 0.10, 0.2, 0.4, 0.6, 0.8, 1.0]),
    supplied_x=("node", "L", "Supplied Execution Pathway share", _SH),
    supplied_a=("node", "L", "Supplied Authority share", _SH),
    iface_closed=("node", "L", "Interface closed to Connections", _SH),
    x_rate=("node", "L", "Admission ease, Execution", _SH),
    a_rate=("node", "L", "Admission ease, Authority", _SH),
    rate_var=("node", "G", "Variation between nodes", [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]),
    visibility=("node", "L", "Node visibility", _SH),
    blind_delay=("node", "L", "Blind-spot delay (9999 = never found)", [10, 25, 50, 100, 200, 9999]),
    chan=("system", "L", "Channel density", _SH),
    g=("system", "L", "Privileged credential exposure (g)", [0.0, 0.05, 0.10, 0.2, 0.4, 0.6, 0.8, 1.0]),
    coverage=("system", "L", "Control Coverage", _SH),
    concentration=("system", "L", "Connections between segments of the same kind", _SH),
    fanout=("operator", "L", "Fan-out", [0.1, 0.2, 0.4, 0.6, 0.8, 1.0]),
    inequality=("operator", "L", "Supplier inequality", [0.0, 0.6, 1.2, 1.8, 2.4, 3.0]),
    redundancy=("operator", "L", "Redundancy (Cut)", [1, 2, 3]),
    theta=("operator", "L", "Dependency threshold", ["any", "majority", "all"]),
    block_delay=("time", "L", "Block delay", [0, 1, 2, 4, 8, 16]),
    c_s=("time", "L", "Structural tempo (C_S)", [5, 10, 20, 40, 80, 160]),
    obs_interval=("time", "L", "Observation interval", [1, 2, 4, 8, 16, 32]),
    detect_latency=("time", "L", "Detection latency", [0, 1, 2, 4, 8, 16]),
    dose=("adaptation", "L", "Adaptation dose", [0.0, 0.01, 0.05, 0.10, 0.2, 0.4, 0.7, 1.0]),
    tac_budget=("adaptation", "L", "Defence capacity (responders per 40 nodes)", [1.0, 2.0, 4.0, 6.0, 8.0, 10.0]),
    def_cap=("adaptation", "L", "Defence Capability (1 to 100)", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    manual_scope=("adaptation", "L", "Manual team works only where automation cannot", [0, 1]),
    auto_clean=("adaptation", "L", "Automated recovery (a block also cleans)", [0, 1]),
    rebuild_time=("adaptation", "L", "Time to rebuild a node or restore a service", [0, 2, 5, 10, 20, 40]),
    manual_delay=("time", "L", "Time to investigate an alarm or a reported compromise", [0, 1, 2, 4, 8, 16]),
    t_clean=("time", "L", "Time to clean a node", [0, 1, 2, 4, 8, 16]),
    t_cut=("time", "L", "Time to cut a relation", [0, 1, 2, 4, 8, 16]),
    queue_order=("adaptation", "L", "Order of the team's work", ["value", "fifo", "degree"]),
    atk_budget=("attacker", "A", "Attacker budget", [1, 2, 3, 4, 5]),
    atk_cap=("attacker", "A", "Attacker Capability (1 to 100)", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    retool=("attacker", "A", "Source re-tooling period", [5, 10, 20, 40, 80, 160]),
    payload_delay=("attacker", "A", "Payload delay (usual)", [0, 1, 2, 4, 8, 16]),
    dormant_share=("attacker", "A", "Share of attacks that lie dormant", [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]),
    dormant_delay=("attacker", "A", "Dormant payload timer", [6, 12, 24, 48, 96, 192]),
    cap_spread=("attacker", "A", "Variation in capability between attacks", [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]),
    node_reconf=("attacker", "A", "Time held before the attacker can act on a node (9999 = never)", [1, 2, 4, 8, 16, 9999]),
    fixed_clock=("attacker", "A", "Share of dormant attacks on one fixed clock", _SH),
    size=("system", "G", "Estate size (nodes)", [50, 100, 200]),
    server_share=("system", "G", "Share of the estate that is servers", _SH),
    remote_share=("system", "L", "Share of endpoints that are remote", _SH),
    cloud_share=("system", "L", "Share of servers in the cloud", _SH),
    seg_ep=("system", "L", "Segmentation of the internal endpoints", [1, 2, 4, 8]),
    seg_sv=("system", "L", "Segmentation of the on-premises servers", [1, 2, 4, 8]),
    ep_conn=("system", "L", "Connections between endpoints of a segment", _SH),
    ep_sv=("system", "L", "Connections from endpoints to servers", _SH),
    cloud_link=("system", "L", "Connections to the cloud", _SH),
    vpn=("system", "L", "Remote access from remote endpoints to servers", _SH),
    ext_exploit=("node", "L", "Entry by Interface, exploit: outward-facing share of servers", _SH),
    n_ext=("system of systems", "L", "External parties (total reach held fixed)", [0, 1, 2, 4, 8, 16]),
    ext_total=("system of systems", "L", "Share of the estate external parties reach", _SH),
    ext_auth=("system of systems", "L", "Share of external parties holding Authority", _SH),
    ext_bad=("system of systems", "G", "Chance an external party is compromised", _SH),
    cloud_bad=("system of systems", "G", "Chance the cloud provider's hypervisor is compromised", _SH),
    ceil_deliv=("system", "L", "Ceiling of the software-delivery Channels", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    ceil_edr=("system", "L", "Ceiling of the endpoint detection Channel", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    ceil_ext=("system of systems", "L", "Ceiling of an external supplier's Channel", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    chan_verify=("system", "L", "Share of delivery Channels that verify their supplier", _SH),
    auth_cred=("system", "L", "Authority needed for Credential Access", [1.0, 20.0, 40.0, 60.0, 80.0, 100.0]),
    exfil_esc=("node", "L", "Chance Exfiltration succeeds after escalation (network control)", _SH),
    sig_block=("node", "L", "Reliability of a known signature on every agent", [0.5, 0.8, 0.9, 0.95, 0.99, 1.0]),
    steal_p=("attacker", "A", "Chance a stealer takes a stored service credential", _SH),
    rotate=("adaptation", "L", "Credential rotation on cleaning (0 none, 1 the node's, 2 the service's)", [0, 1, 2]),
    cred_ttl=("time", "L", "Ticks a stolen credential stays valid (9999 = until rotated)", [10, 20, 40, 80, 160, 9999]),
    handoff=("attacker", "A", "Campaign: ticks of stealer payloads before the intrusion begins", [0, 10, 20, 40, 80, 160]),
    c2_share=("system", "L", "Command and Control: share of nodes with a route out", _SH),
    exfil_p=("node", "L", "Chance an Exfiltration attempt succeeds", _SH),
    objective=("attacker", "A", "Does the payload exfiltrate", ["steal", "destroy"]),
    val_sv=("system", "G", "Node value of a server (an endpoint is 1)", [1.0, 5.0, 10.0, 16.0, 20.0, 40.0]),
    dval_sv=("system", "G", "Data value of a server (an endpoint is 1)", [1.0, 5.0, 10.0, 20.0, 40.0, 80.0]),
    exc_share=("system", "G", "Share of endpoints with exceptional data value", [0.0, 0.02, 0.05, 0.1, 0.2, 0.4]),
    edr_site=("system of systems", "L", "Endpoint detection sited with a third party (0 inside, 1 outside)", [0, 1]),
    dns_site=("system of systems", "L", "DNS sited with a third party (0 inside, 1 outside)", [0, 1]),
    zone_conn=("system", "L", "Connections between servers of a segment", [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]),
    ad_reach=("system", "L", "Active Directory reach", _SH),
    managed=("system", "L", "Managed share of the control", _SH),
    hand_delay=("time", "L", "Hand-update delay for an unmanaged control", [2, 6, 12, 24, 48, 96]),
    reconf_time=("time", "A", "Reconfigure time after a controller falls", [0, 1, 2, 4, 8, 16]),
    ctl_link=("system", "L", "Controller link (0 none, 1 neighbours, 2 all)", [0, 1, 2]),
    repl_delay=("time", "L", "Replication delay between controllers (9999 = never)", [0, 2, 4, 8, 16, 32, 9999]),
    dns=("system", "L", "DNS as an estate-wide Channel over the other Channels", [0, 1]),
    n_chan=("system", "L", "Software-delivery channels", [0, 1, 2, 3, 4, 5]),
    chan_cov=("system", "L", "Delivery channel coverage", _SH),
    chan_span=("system", "L", "Delivery channels shared across zones", _SH),
    stage_time=("time", "L", "Staged rollout on delivery channels", [0, 2, 4, 8, 16, 32]),
    cap_drift=("attacker", "A", "Security drift (capability gained per 100 ticks)",
               [0.0, 0.05, 0.10, 0.25, 0.50, 1.0]),
)
CONN_LADDER = dict(mesh=[2.0, 4.0, 6.0, 8.0, 10.0, 12.0], chain=[0.0, 0.5, 1.0, 1.5, 2.0, 3.0],
                   star=[0.0, 0.5, 1.0, 1.5, 2.0, 3.0])
WHO = dict(L="defender lever", A="attacker", G="given")
# knobs that only act in the presence of another: the structural tempo only when the
# defender adapts, the blind-spot delay only when some nodes cannot be seen. Their
# ladders are run at the stated level of the other knob, and compared with it.
NEEDS = {"c_s": ("dose", 0.05), "blind_delay": ("visibility", 0.5)}
# knobs that only exist when systems are separately governed
GAMMA1_ONLY = set()

SCREEN = dict(
    topologies=["chain", "star", "mesh"],
    gammas=[0, 1],
    # Grid re-established on the frozen model on 13 October (--mode grid, 5 x 5
    # map, every kind, both backgrounds). Recovery (the block cadence) moves no
    # outcome for any kind, and spread (the attacker cadence) moves only malware
    # (7 points of furthest reached); for the other kinds most cells of the old
    # grid were the same run repeated. The grid is therefore three spread
    # levels at one recovery level, and replication comes from seeds and wirings.
    spread=[1, 16, 256],
    recovery=[8],
    seeds_a=[6101, 6102, 6103, 6104],        # dynamics seed blocks (pilot)
    seeds_b=[6201, 6202, 6203, 6204],        # second set, for the repeat-run noise measure
    reps=1,
    wirings=[6001, 6002, 6003],              # wirings every knob level is run on
    neutral_wirings=list(range(6001, 6013)), # wirings of the neutral ensemble (12)
    confirmatory_seeds_reserved=[7101, 7201, 7202, 7301],   # NOT used by any screening mode
    threshold_percentile=99.0,               # of the noise distribution
)


# Backgrounds of the sweep. A knob's effect depends on where the other dials
# sit, so every knob's ladder is run against several backgrounds. A background
# moves the defender's operating dials together to one position along their own
# ladders, counted from the end that is worse for the defender (0) to the end
# that is better (1). These are positions on a range and nothing more: none is
# claimed to be typical. "neutral" leaves every dial at the register's neutral
# value. The dials that move, and the end of each ladder that is better for the
# defender (+1 the last level, -1 the first):
BACKGROUND_DIALS = dict(visibility=+1, coverage=+1, tac_budget=+1, def_cap=+1,
                        blind_delay=-1, detect_latency=-1, obs_interval=-1, block_delay=-1,
                        manual_delay=-1)
# Backgrounds checked on the v0.9 model before any sweep (12 October). With the
# privileged credentials exposed on 5 per cent of nodes, the flag is captured in
# about a third of runs at the strong position and in every run, within about 36
# ticks, at every weaker position (0.8, 0.6 and 0.4 give the same result), so a
# third position on the same scale would add nothing. With no credential exposed
# the flag is never captured and the attack is propagation only. The three
# backgrounds are therefore: strong; middle; and sealed, which is the middle
# position with no credential exposed, so that the dials acting on propagation
# can be seen where the master route does not decide everything.
BACKGROUND_POSITIONS = dict(strong=1.0, middle=0.6, sealed=0.6)
BACKGROUND_EXTRA = dict(sealed=dict(g=0.0))
BACKGROUND_NOTE = dict(sealed="no privileged credential exposed")


def _background(pos: float) -> dict:
    out = {}
    for k, better in BACKGROUND_DIALS.items():
        lv = list(REGISTER[k][3])
        if better < 0:
            lv = lv[::-1]
        v = lv[int(round(pos * (len(lv) - 1)))]
        out[k] = type(getattr(Knobs(), k))(v)
    return out


POINTS = dict(neutral={}, **{name: dict(_background(p), **BACKGROUND_EXTRA.get(name, {}))
                              for name, p in BACKGROUND_POSITIONS.items()})
_POINT = ["neutral"]

# Attack kinds, one per relation class of Paper 1B, and a precursor. In Paper 4C
# every run sends one kind only, so the result is a table of dial against kind.
#   malware    travels on Connections: enters by Interface, spreads to its
#              neighbours unaided, cannot use a credential, leaves a signature
#   implant    travels on a Channel: arrives from a compromised external
#              supplier, lies dormant, and once active is operated by hand
#   intrusion  travels on Authority: enters by Interface or with authority
#              obtained outside, moves by hand a few steps per tick, uses
#              credentials, and leaves no signature (malware-free)
#   stealer    the precursor: enters by Interface, does not spread, and harvests
#              the node it lands on
#   mixed      everything at once (not used in the 4C sweep)
#   campaign   the precursor at work: stealer payloads for `handoff` ticks, then
#              intrusion payloads from the same attacker, using what was stolen
KINDS = ("malware", "implant", "intrusion", "stealer", "campaign")
_KIND = ["mixed"]


def set_kind(name: str):
    if name not in KINDS + ("mixed",):
        raise ValueError(f"unknown attack kind {name}")
    _KIND[0] = name



def set_point(name: str):
    if name not in POINTS:
        raise ValueError(f"unknown background {name}")
    _POINT[0] = name


def ladder(knob: str, topology: str, steps: int = 99) -> list:
    lv = CONN_LADDER[topology] if knob == "conn" else REGISTER[knob][3]
    lv = list(lv)
    if steps < len(lv) and all(isinstance(x, (int, float)) for x in lv):
        idx = sorted(set(int(round(i * (len(lv) - 1) / (steps - 1))) for i in range(steps)))
        lv = [lv[i] for i in idx]
    return lv


def design(topology: str, gamma: int, steps: int = 99, knobs: Optional[List[str]] = None,
           cap_rule: str = "ratio") -> List[dict]:
    """The ladder screen for one stratum: every knob stepped across its range
    from the neutral point, one knob at a time. Each entry is one configuration
    (run on several wirings); `ref` names the configuration it is compared with."""
    N = Knobs(topology=topology, cap_rule=cap_rule, kind=_KIND[0], **POINTS[_POINT[0]])
    out = [dict(name="neutral", knob=None, level=None, kn=N, ref=None)]
    names = {"neutral"}

    def add(name, knob, level, kn, ref):
        if name not in names:
            names.add(name)
            out.append(dict(name=name, knob=knob, level=level, kn=kn, ref=ref))

    for knob in REGISTER:
        if knobs and knob not in knobs:
            continue
        if knob in GAMMA1_ONLY and gamma == 0:
            continue
        base, ref = N, "neutral"
        if knob in NEEDS:
            other, val = NEEDS[knob]
            base = dataclasses.replace(N, **{other: val})
            ref = f"{other}={val}"
            add(ref, other, val, base, "neutral")
        if knob == "theta":
            # a majority differs from all only with three suppliers
            base = dataclasses.replace(N, redundancy=3)
            ref = "redundancy=3"
            add(ref, "redundancy", 3, base, "neutral")
        neutral_value = base.conn_value() if knob == "conn" else getattr(base, knob)
        for lv in ladder(knob, topology, steps):
            if lv == neutral_value:
                continue
            kn_lv = dataclasses.replace(base, **{knob: lv})
            add(f"{knob}={lv}", knob, lv, kn_lv, ref)
    return out
# ==== MODEL ENDS ====
# Everything between the two markers above is the model: the frozen cemt core,
# the 4B engine lifted verbatim, Engine4C, the generator and the dial register.
# Everything below is analysis and runners. MODEL_DIGEST hashes the model text
# alone, so an analysis-only change (v0.19, v0.20) leaves it unchanged, and a
# run record whose MODEL_DIGEST matches a frozen version's ran the same model.


def _model_digest() -> str:
    try:
        src = open(os.path.abspath(__file__), encoding="utf-8").read()
        a = src.index("# ==== MODEL BEGINS ====\n") + len("# ==== MODEL BEGINS ====\n")
        b = src.index("# ==== MODEL ENDS ====\n")
        return hashlib.sha256(src[a:b].encode("utf-8")).hexdigest()
    except Exception:
        return "unavailable"


MODEL_DIGEST = _model_digest()
# the model as frozen on 18 October for the final confirmation (PhDPaper4C v0.18)
MODEL_DIGEST_V018 = "f52777fbcb8db06d456f1f95bed8750a4cd02bdd270f85718f59086a6e73a0f0"



# ============================================================================
# Running one task: one configuration on one wiring, the two-start test over
# the spread x recovery grid
# ============================================================================
CLEAN_KEYS = ("f", "fa", "ks", "pk", "ar", "tm", "tc", "tk", "nk", "mh", "dh", "ih",
              "fl", "tf", "r1", "r2", "r3", "im", "ni", "nr", "sv", "hv", "pl", "ex", "al",
              "r0", "wf", "fv", "sl", "sd", "dl", "dn", "ne", "nw", "qm", "qw",
              "d24", "s24", "c24", "d72", "s72", "c72", "d168", "s168", "c168", "nh", "nc", "nt",
              "cs", "cu", "cv")
COLL_KEYS = ("f", "fa", "ks", "ar")


def run_one(spec, layout, net, kn: Knobs, spread: int, recovery: int, init, seed: int) -> dict:
    eng = Engine4C(spec, make_cfg(kn, spread, recovery, seed), layout,
                   net=net_for_seed(net, seed), opts=make_opts(kn))
    eng.start(init)
    eng.run()
    return eng.outcome()


def task_key(t) -> str:
    name, kn_dict, gamma, seedset = t[0], t[1], t[2], t[3]
    return f"{kn_dict['topology']}|{gamma}|{name}|{kn_dict['wiring_seed']}|{seedset}"


def run_task(task) -> dict:
    """Top-level and picklable. Returns everything the analysis needs."""
    name, kn_dict, gamma, seedset, spread, recovery, seeds, reps = task
    kn = Knobs(**kn_dict)
    spec, layout, built = generate(kn, gamma)
    net = _core_build_network(spec, np.random.default_rng(kn.wiring_seed))
    cells = []
    for sp in spread:
        for rc in recovery:
            c = {k: [] for k in CLEAN_KEYS}
            x = {k: [] for k in COLL_KEYS}
            for s in seeds:
                for r in range(reps):
                    rs = s * 1000 + r
                    o = run_one(spec, layout, net, kn, sp, rc, None, rs)
                    for k in CLEAN_KEYS:
                        c[k].append(round(o[k], 4) if isinstance(o[k], float) else o[k])
                    # v0.9: one start. The estate always begins clean (no system
                    # starts pre-infected); the second start of Paper 4B is not run
                    for k in COLL_KEYS:
                        x[k].append(round(o[k], 4))
            cells.append(dict(sp=sp, rc=rc, c=c, x=x))
    return dict(key=task_key(task), name=name, topology=kn.topology, gamma=gamma,
                wiring=kn.wiring_seed, seedset=seedset, cells=cells,
                realised=realised(kn, built))


def build_tasks(topologies, gammas, steps, knobs=None, cap_rule="ratio") -> List[tuple]:
    """Neutral ensembles first (both seed sets), then the knobs in register
    order, each knob completed across every stratum before the next begins, so
    a run that is stopped early still holds whole knobs."""
    S = SCREEN
    sp, rc = tuple(S["spread"]), tuple(S["recovery"])
    A, B = tuple(S["seeds_a"]), tuple(S["seeds_b"])
    tasks, per = [], {}
    for t in topologies:
        for g in gammas:
            per[(t, g)] = design(t, g, steps, knobs, cap_rule)
            N = per[(t, g)][0]["kn"]
            for ws in S["neutral_wirings"]:
                d = dataclasses.asdict(dataclasses.replace(N, wiring_seed=ws))
                tasks.append(("neutral", d, g, "a", sp, rc, A, S["reps"]))
                tasks.append(("neutral", d, g, "b", sp, rc, B, S["reps"]))
    order = []
    for (t, g), cfgs in per.items():
        for c in cfgs[1:]:
            if c["name"] not in order:
                order.append(c["name"])
    for name in order:
        for (t, g), cfgs in per.items():
            for c in cfgs:
                if c["name"] != name:
                    continue
                for ws in S["wirings"]:
                    d = dataclasses.asdict(dataclasses.replace(c["kn"], wiring_seed=ws))
                    tasks.append((name, d, g, "a", sp, rc, A, S["reps"]))
    return tasks


# ============================================================================
# Analysis: the size of each knob's effect on the outcome grid, against noise
# ============================================================================
FAMILIES = dict(
    C="the flag (80 per cent of the estate compromised: game over)",
    S="zones lost (share of zones more than half compromised at the end)",
    R="survival (share of the horizon for which the estate stays standing)",
    A="compromise while standing (average share compromised until the flag or the end)",
)


def _vec(res: dict) -> Dict[str, np.ndarray]:
    """One task's outcome grid, one value per cell, for each outcome family."""
    C, S, R, A, F, X = [], [], [], [], [], []
    for cell in res["cells"]:
        c, x = cell["c"], cell["x"]
        C.append(np.mean(c["fl"]) if "fl" in c else np.mean([v > 0.5 for v in c["f"]]))
        S.append(np.mean(c["ks"]))
        R.append(np.mean(c["sv"]) if "sv" in c else np.mean(c["pk"]))
        A.append(np.mean(c["ar"]))
        F.append(np.mean(c["f"]))
        X.append(np.mean(c["f"]))
    return dict(C=np.array(C), S=np.array(S), R=np.array(R), A=np.array(A),
                F=np.array(F), X=np.array(X))


def _mean_vecs(vs: List[Dict[str, np.ndarray]]) -> Dict[str, np.ndarray]:
    return {k: np.mean([v[k] for v in vs], axis=0) for k in vs[0]}


def _effect(a: Dict[str, np.ndarray], b: Dict[str, np.ndarray]) -> Dict[str, Tuple[float, float]]:
    """(size, signed) of the difference a - b per family, averaged over the grid."""
    return {k: (float(np.mean(np.abs(a[k] - b[k]))), float(np.mean(a[k] - b[k])))
            for k in FAMILIES}


def _band_cells(v: Dict[str, np.ndarray]) -> int:
    lo, hi = v["F"], v["X"]
    return int(((lo <= E8["lo_max"]) & (hi >= E8["hi_min"]) & (hi - lo >= E8["tau"])).sum())


def _how_it_falls(tasks: List[dict]) -> dict:
    tm, first, nk, mh, anyk, dh, ih, n = [], [], [], [], [], [], [], 0
    fl, pk, tf, r1, r2, r3, im, sv, hv = [], [], [], [], [], [], [], [], []
    ex, al = [], []
    r0, fv, sl, sd, dl, dn, ne, nw, qm, qw = [], [], [], [], [], [], [], [], [], []
    for res in tasks:
        for cell in res["cells"]:
            c = cell["c"]
            for i in range(len(c["f"])):
                n += 1
                nk.append(c["nk"][i])
                anyk.append(1.0 if c["ks"][i] > 0 else 0.0)
                if "mh" in c:
                    mh.append(c["mh"][i])
                if "dh" in c:
                    dh.append(c["dh"][i]); ih.append(c["ih"][i])
                pk.append(c["pk"][i])
                if "fl" in c:
                    fl.append(c["fl"][i]); im.append(c["im"][i]); sv.append(c["sv"][i])
                    if "hv" in c:
                        hv.append(c["hv"][i])
                    if "ex" in c:
                        ex.append(c["ex"][i]); al.append(c["al"][i])
                    # the engine reports each route as a share of the nodes held; as a
                    # share of the estate it is steadier when few nodes are held
                    f_ = c["f"][i]
                    r1.append(c["r1"][i] * f_); r2.append(c["r2"][i] * f_); r3.append(c["r3"][i] * f_)
                    if "sl" in c:
                        r0.append(c["r0"][i] * f_); fv.append(c["fv"][i]); sl.append(c["sl"][i])
                        sd.append(c["sd"][i]); dl.append(c["dl"][i]); dn.append(c["dn"][i])
                        ne.append(c["ne"][i]); nw.append(c["nw"][i]); qm.append(c["qm"][i]); qw.append(c["qw"][i])
                    if c["fl"][i]:
                        tf.append(c["tf"][i])
                if c["tm"][i] >= 0:
                    tm.append(c["tm"][i])
                    tk, tc = c["tk"][i], c["tc"][i]
                    first.append(1.0 if (tk >= 0 and (tc < 0 or tk <= tc)) else 0.0)
    return dict(reach_majority=len(tm) / max(n, 1),
                median_time_to_majority=float(np.median(tm)) if tm else float("nan"),
                master_first=float(np.mean(first)) if first else float("nan"),
                masters_captured=float(np.mean(nk)) if nk else float("nan"),
                any_system_lost=float(np.mean(anyk)) if anyk else float("nan"),
                masters_held=float(np.mean(mh)) if mh else float("nan"),
                defence_plane_held=float(np.mean(dh)) if dh else float("nan"),
                identity_plane_held=float(np.mean(ih)) if ih else float("nan"),
                flag=float(np.mean(fl)) if fl else float("nan"),
                peak=float(np.mean(pk)) if pk else float("nan"),
                median_time_to_flag=float(np.median(tf)) if tf else float("nan"),
                route_conn=float(np.mean(r1)) if r1 else float("nan"),
                route_chan=float(np.mean(r2)) if r2 else float("nan"),
                route_ctrl=float(np.mean(r3)) if r3 else float("nan"),
                impact=float(np.mean(im)) if im else float("nan"),
                survival=float(np.mean(sv)) if sv else float("nan"),
                harvested=float(np.mean(hv)) if hv else float("nan"),
                excluded=float(np.mean(ex)) if ex else float("nan"),
                alarms=float(np.mean(al)) if al else float("nan"),
                route_entry=float(np.mean(r0)) if r0 else float("nan"),
                value_flag=float(np.mean(fv)) if fv else float("nan"),
                service_loss=float(np.mean(sl)) if sl else float("nan"),
                defender_loss=float(np.mean(sd)) if sd else float("nan"),
                data_loss=float(np.mean(dl)) if dl else float("nan"),
                down=float(np.mean(dn)) if dn else float("nan"),
                escalations=float(np.mean(ne)) if ne else float("nan"),
                escalations_won=float(np.mean(nw)) if nw else float("nan"),
                backlog=float(np.mean(qm)) if qm else float("nan"),
                wait=float(np.mean(qw)) if qw else float("nan"))


def _sd_wirings(tasks: List[dict]) -> dict:
    """Spread of the main outcomes between wirings: the standard deviation of
    the per-wiring means of the flag and of the furthest reach."""
    per = [_how_it_falls([x]) for x in tasks]
    sd = lambda k: float(np.std([p[k] for p in per])) if len(per) > 1 and all(np.isfinite(p[k]) for p in per) else float("nan")
    return dict(flag_sd_wirings=sd("flag"), peak_sd_wirings=sd("peak"), data_loss_sd_wirings=sd("data_loss"))


def analyse_results(results: List[dict]) -> dict:
    import itertools
    S = SCREEN
    idx: Dict[tuple, dict] = {}
    for r in results:
        idx[(r["topology"], r["gamma"], r["name"], r["wiring"], r["seedset"])] = r
    strata = sorted({(r["topology"], r["gamma"]) for r in results},
                    key=lambda s: (S["topologies"].index(s[0]) if s[0] in S["topologies"] else 9, s[1]))
    W = S["wirings"]
    out = dict(strata=[], curves=[], knobs=[], notes=[], noise={})
    for (t, g) in strata:
        NA = {w: _vec(idx[(t, g, "neutral", w, "a")]) for w in S["neutral_wirings"]
              if (t, g, "neutral", w, "a") in idx}
        NB = {w: _vec(idx[(t, g, "neutral", w, "b")]) for w in S["neutral_wirings"]
              if (t, g, "neutral", w, "b") in idx}
        both = [w for w in NA if w in NB]
        if len(NA) < len(W) + 1 or len(both) < len(W) or not all(w in NA for w in W):
            out["notes"].append(f"{t} gamma={g}: neutral ensemble incomplete "
                                f"({len(NA)} wirings); stratum not analysed")
            continue
        # ---- noise: what a knob that does nothing looks like ------------------
        paired = {k: [] for k in FAMILIES}      # same wirings, different run seeds
        unpaired = {k: [] for k in FAMILIES}    # different wirings
        for sub in itertools.combinations(both, len(W)):
            e = _effect(_mean_vecs([NA[w] for w in sub]), _mean_vecs([NB[w] for w in sub]))
            for k in FAMILIES:
                paired[k].append(e[k][0])
        allw = list(NA)
        for sub in itertools.combinations(allw, len(W)):
            rest = [w for w in allw if w not in sub]
            e = _effect(_mean_vecs([NA[w] for w in sub]), _mean_vecs([NA[w] for w in rest]))
            for k in FAMILIES:
                unpaired[k].append(e[k][0])
        p = S["threshold_percentile"]
        thr_p = {k: max(float(np.percentile(paired[k], p)), 1e-6) for k in FAMILIES}
        thr_u = {k: max(float(np.percentile(unpaired[k], p)), 1e-6) for k in FAMILIES}
        ens = _mean_vecs(list(NA.values()))
        neutral_tasks = [idx[(t, g, "neutral", w, "a")] for w in NA]
        # the neutral point on the screen wirings alone, so that a dial's levels
        # and its base are compared on the same wirings and seeds (v0.20)
        ens_w = _mean_vecs([NA[w] for w in W])
        tasks_w = [idx[(t, g, "neutral", w, "a")] for w in W]
        base_w = dict(collapse=float(ens_w["C"].mean()), per_system=float(ens_w["S"].mean()),
                      reversal_fails=float(ens_w["R"].mean()), compromise=float(ens_w["A"].mean()),
                      band_cells=_band_cells(ens_w), **_how_it_falls(tasks_w), **_sd_wirings(tasks_w))
        out["noise"][f"{t}|{g}"] = dict(paired=thr_p, unpaired=thr_u, n_wirings=len(NA))
        out["strata"].append(dict(
            topology=t, gamma=g, neutral_wirings=len(NA),
            collapse=float(ens["C"].mean()), per_system=float(ens["S"].mean()),
            reversal_fails=float(ens["R"].mean()), compromise=float(ens["A"].mean()),
            band_cells=_band_cells(ens), **_how_it_falls(neutral_tasks),
            **{f"noise_{k}": thr_p[k] for k in FAMILIES}, base=base_w))
        # ---- every configuration against its reference ---------------------------
        cfgs = design(t, g, steps=99)
        byname = {c["name"]: c for c in cfgs}
        have = {}
        for c in cfgs:
            ts = [idx.get((t, g, c["name"], w, "a")) for w in W]
            if all(x is not None for x in ts):
                have[c["name"]] = ts
        vecs = {n_: _mean_vecs([_vec(x) for x in ts]) for n_, ts in have.items()}
        per_knob: Dict[str, List[dict]] = {}
        for n_, ts in have.items():
            c = byname[n_]
            if c["knob"] is None or c["ref"] not in vecs:
                continue
            e = _effect(vecs[n_], vecs[c["ref"]])
            eu = _effect(vecs[n_], ens) if c["ref"] == "neutral" else None
            row = dict(topology=t, gamma=g, knob=c["knob"], level=c["level"], config=n_,
                       reference=c["ref"],
                       collapse=float(vecs[n_]["C"].mean()), per_system=float(vecs[n_]["S"].mean()),
                       reversal_fails=float(vecs[n_]["R"].mean()),
                       compromise=float(vecs[n_]["A"].mean()),
                       band_cells=_band_cells(vecs[n_]), **_how_it_falls(ts), **_sd_wirings(ts))
            for k in FAMILIES:
                row[f"ratio_{k}"] = e[k][0] / thr_p[k]
                row[f"signed_{k}"] = e[k][1]
                row[f"ratio_wirings_{k}"] = (eu[k][0] / thr_u[k]) if eu else float("nan")
            out["curves"].append(row)
            per_knob.setdefault(c["knob"], []).append(row)
        # ---- knob summaries --------------------------------------------------------
        for knob, rows in per_knob.items():
            layer, who, label, _ = REGISTER[knob]
            ref_kn = byname[rows[0]["reference"]]["kn"]
            ref_level = ref_kn.conn_value() if knob == "conn" else getattr(ref_kn, knob)
            rec = dict(topology=t, gamma=g, knob=knob, label=label, layer=layer, who=WHO[who],
                       levels=len(rows))
            best = "none"
            for k in FAMILIES:
                ratios = [r[f"ratio_{k}"] for r in rows]
                n_clear = sum(1 for x in ratios if x > 1.0)
                need = 2 if len(rows) >= 3 else len(rows)
                cls = "clear" if n_clear >= need else ("possible" if n_clear >= 1 else "none")
                # direction across the whole ladder, the reference level counting as
                # a zero change at its own position
                pts = [(_lv(r["level"], knob), r[f"signed_{k}"]) for r in rows] + [(_lv(ref_level, knob), 0.0)]
                pts.sort(key=lambda p: p[0])
                span = pts[-1][1] - pts[0][1]
                rec[f"class_{k}"] = cls
                rec[f"max_ratio_{k}"] = max(ratios)
                rec[f"clear_levels_{k}"] = n_clear
                rec[f"rises_with_knob_{k}"] = span
                if VERDICTS.index(cls) < VERDICTS.index(best):
                    best = cls
            rec["class_any"] = best
            rec["band_closes"] = any(r["band_cells"] == 0 for r in rows)
            out["knobs"].append(rec)
    return out


VERDICTS = ["clear", "possible", "none"]


def _lv(level, knob=None):
    """Position of a level on its dial, for ordering a ladder. Numeric levels
    order by value; a named level by its place in the dial's ladder (theta's
    any/majority/all, the team's queue order, the attacker's objective). A
    named reference that is not on the ladder (objective "kind", the payload
    deciding) sits before the ladder at -1."""
    if isinstance(level, str):
        lad = list(REGISTER[knob][3]) if knob in REGISTER else []
        if level in lad:
            return float(lad.index(level))
        if level in THETA_LEVELS:
            return float(THETA_LEVELS.index(level))
        return -1.0
    return float(level)


# ============================================================================
# Output
# ============================================================================
def _csv(path: str, rows: List[dict]):
    if not rows:
        return
    cols = list(rows[0].keys())
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)

    def cell(v):
        if isinstance(v, float):
            return "" if not np.isfinite(v) else f"{v:.6g}"
        s = str(v)
        return '"' + s.replace('"', "'") + '"' if ("," in s or "\n" in s) else s
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(",".join(cols) + "\n")
        for r in rows:
            f.write(",".join(cell(r.get(c, "")) for c in cols) + "\n")


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (np.bool_,)):
        return bool(o)
    return str(o)


def write_record(run_dir: str, mode: str, extra: dict):
    rec = dict(code_version=CODE_VERSION, spec_version=SPEC_VERSION, engine_base=ENGINE_BASE,
               mode=mode, utc=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
               frozen_core_digest=EMBEDDED_SET_DIGEST,
               model_digest=MODEL_DIGEST, model_same_as_v0_18=(MODEL_DIGEST == MODEL_DIGEST_V018),
               frozen_core_verified=bool(all(_FREEZE_REPORT.values())),
               citable=mode in ("confirm", "drill"),
               note=("Pre-specified study on the reserved seeds: the protocol is in this record." if mode in ("confirm", "drill")
                     else "Screening or pilot pass on pilot seeds: finds which knobs matter. Not a confirmatory run."),
               screen=SCREEN, starting_point=_POINT[0],
               attack_kind=_KIND[0],
               neutral=dataclasses.asdict(Knobs(kind=_KIND[0], **POINTS[_POINT[0]])),
               register={k: dict(layer=v[0], who=WHO[v[1]], label=v[2], ladder=v[3])
                         for k, v in REGISTER.items()},
               conn_ladder=CONN_LADDER, e8=E8, python=sys.version.split()[0], numpy=np.__version__)
    rec.update(extra)
    with open(os.path.join(run_dir, "run_record.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, default=_json_default)


def _f(v, nd=2):
    return "-" if (v is None or (isinstance(v, float) and not np.isfinite(v))) else f"{v:.{nd}f}"


def load_results(run_dir: str) -> List[dict]:
    path = os.path.join(run_dir, "results.jsonl")
    out = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue          # a line cut short by an interrupted run
                out[r["key"]] = r
    return list(out.values())


def write_screen(run_dir: str, results: List[dict], an: dict, n_planned: Optional[int] = None):
    _csv(os.path.join(run_dir, "curves.csv"), an["curves"])
    _csv(os.path.join(run_dir, "knobs.csv"), an["knobs"])
    _csv(os.path.join(run_dir, "neutral.csv"), an["strata"])
    _csv(os.path.join(run_dir, "realised.csv"),
         [dict(topology=r["topology"], gamma=r["gamma"], config=r["name"], wiring=r["wiring"],
               **r["realised"]) for r in results if r["seedset"] == "a"])
    strata = [(s["topology"], s["gamma"]) for s in an["strata"]]
    K = {}
    for k in an["knobs"]:
        K[(k["knob"], k["topology"], k["gamma"])] = k
    knobs = [k for k in REGISTER if any((k, t, g) in K for (t, g) in strata)]
    head = " | ".join(f"{t} g={g}" for (t, g) in strata)
    L = [f"# Paper 4C screening pass ({CODE_VERSION}), attack kind: {_KIND[0]}, background: {_POINT[0]}", "",
         f"{SPEC_VERSION}. Frozen core {EMBEDDED_SET_DIGEST[:12]} verified. Pilot seeds. "
         "This pass asks which knobs change the outcome and how strongly. It makes no reading "
         "against any hypothesis.", "",
         f"Tasks completed: {len(results)}" + (f" of {n_planned}" if n_planned else "") + ". "
         f"Each knob level is run on {len(SCREEN['wirings'])} wirings, "
         f"{len(SCREEN['spread'])} x {len(SCREEN['recovery'])} grid cells, 2 starts, "
         f"{len(SCREEN['seeds_a']) * SCREEN['reps']} runs per cell and start.", "",
         "## 1. The neutral point", "",
         "| stratum | flag captured | at least one zone lost | zones lost | "
         "controllers held at the end | zones with no automated defence | zones the defender is excluded from | survival | "
         "share of run compromised | band cells | master falls first | noise C | noise R | noise A |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in an["strata"]:
        L.append(f"| {s['topology']} g={s['gamma']} | {_f(s['collapse'])} | "
                 f"{_f(s.get('any_system_lost'))} | {_f(s['per_system'])} | {_f(s.get('masters_held'))} | "
                 f"{_f(s.get('defence_plane_held'))} | {_f(s.get('identity_plane_held'))} | "
                 f"{_f(s['reversal_fails'])} | {_f(s['compromise'])} | {s['band_cells']} of "
                 f"{len(SCREEN['spread']) * len(SCREEN['recovery'])} | {_f(s['master_first'])} | "
                 f"{_f(s['noise_C'], 3)} | {_f(s['noise_R'], 3)} | {_f(s['noise_A'], 3)} |")
    L += ["", "All values are averages over the spread and recovery grid. 'Band cells' counts grid "
          "cells where a clean start stays contained and a collapsed start stays collapsed; zero "
          "is a legitimate value. 'Flag captured' is the share of runs in which 80 per cent of the estate was "
          "compromised, at which point the run stops; 'at least one system lost' is the share of runs ending with any one system more "
          "than half compromised, which the first measure does not see; 'masters held' is the "
          "share of management masters in the attacker's hands at the end; 'defence plane held' and "
          "'identity plane held' are the shares of systems whose endpoint protection master and "
          "whose identity master are in the attacker's hands at the end. 'Master falls first' is the share of collapsing runs in which a "
          "management master was captured before any system fell. 'Noise' is the "
          f"{SCREEN['threshold_percentile']:.0f}th percentile of the difference between repeat "
          "runs of the neutral point on the same wirings: a knob's effect is reported as a "
          "multiple of it.", ""]

    def matrix(title, fams, note):
        M = [f"## {title}", "", note, "", f"| knob | layer | who moves it | {head} |",
             "|---|---|---|" + "---|" * len(strata)]
        for k in knobs:
            cells = []
            for (t, g) in strata:
                r = K.get((k, t, g))
                if r is None:
                    cells.append("-")
                    continue
                ratio = max(r[f"max_ratio_{f_}"] for f_ in fams)
                cls = min((r[f"class_{f_}"] for f_ in fams), key=VERDICTS.index)
                txt = f"{ratio:.1f}"
                cells.append(f"**{txt}**" if cls == "clear" else (f"{txt}?" if cls == "possible" else txt))
            layer, who, label, _ = REGISTER[k]
            M.append(f"| {label} | {layer} | {WHO[who]} | " + " | ".join(cells) + " |")
        return M + [""]

    key = ("Each cell is the knob's largest effect as a multiple of noise. **Bold**: clears the "
           "noise at two or more levels. A question mark: clears it at one level only. Plain: "
           "inside the noise.")
    L += matrix("2. Catastrophe: does the knob change whether the estate collapses?", ("C", "S"), key)
    L += matrix("3. Survival: does the knob change how long the estate stands?", ("R",), key)
    L += matrix("4. Compromise: does the knob change how much is compromised?", ("A",), key)

    # ranking
    rank = []
    for k in knobs:
        rs = [K[(k, t, g)] for (t, g) in strata if (k, t, g) in K]
        cat = [max(r["max_ratio_C"], r["max_ratio_S"]) for r in rs]
        n_clear = sum(1 for r in rs if "clear" in (r["class_C"], r["class_S"]))
        direction = np.mean([r["rises_with_knob_C"] for r in rs])
        rank.append((float(np.mean(cat)), k, n_clear, len(rs), direction,
                     any(r["band_closes"] for r in rs)))
    rank.sort(reverse=True)
    L += ["## 5. Ranking on catastrophe", "",
          "| rank | knob | who moves it | mean effect (x noise) | strata clear | "
          "collapse as the knob rises | band closes at some level |", "|---|---|---|---|---|---|---|"]
    for i, (mean_r, k, n_clear, n_s, direction, closes) in enumerate(rank, 1):
        layer, who, label, _ = REGISTER[k]
        d = "more" if direction > 0.02 else ("less" if direction < -0.02 else "no clear trend")
        L.append(f"| {i} | {label} | {WHO[who]} | {mean_r:.1f} | {n_clear} of {n_s} | {d} | "
                 f"{'yes' if closes else 'no'} |")
    L += [""]

    def fam_clear(r, fams):
        return any(r[f"class_{f_}"] == "clear" for f_ in fams)
    only_cat, only_comp = [], []
    for k in knobs:
        rs = [K[(k, t, g)] for (t, g) in strata if (k, t, g) in K]
        cat = sum(1 for r in rs if fam_clear(r, ("C", "S", "R")))
        comp = sum(1 for r in rs if fam_clear(r, ("A",)))
        if cat and not comp:
            only_cat.append(REGISTER[k][2])
        if comp and not cat:
            only_comp.append(REGISTER[k][2])
    L += ["## 6. Catastrophe as distinct from compromise", "",
          "- Move catastrophe or reversal, but not the amount compromised: "
          + (", ".join(only_cat) or "none"),
          "- Move the amount compromised, but not catastrophe or reversal: "
          + (", ".join(only_comp) or "none"), ""]
    drop = [REGISTER[k][2] for k in knobs
            if all(K[(k, t, g)]["class_any"] == "none" for (t, g) in strata if (k, t, g) in K)]
    L += ["## 7. Candidates to drop", "",
          "Inside the noise for every outcome in every stratum analysed: "
          + (", ".join(drop) or "none") + ".", "",
          "This pass turns one knob at a time from the neutral point, so it cannot see a knob "
          "that only matters in combination. Under the methodology's drop rule a knob is "
          "eliminated only after the walks from other starting points also show nothing. These "
          "are candidates, not eliminations.", ""]
    if an["notes"]:
        L += ["## Notes", ""] + [f"- {n_}" for n_ in an["notes"]] + [""]
    L += ["## Pass log (to complete)", "", "1. **Found:**", "2. **Changed** (measurement fix or "
          "model change, with reason):", "3. **Dropped:**", "4. **Next:**", "",
          "## Files", "",
          "- `curves.csv` one row per knob level: every outcome, the band, how the estate falls, "
          "and the effect as a multiple of noise.",
          "- `knobs.csv` one row per knob and stratum.",
          "- `neutral.csv` the neutral point and noise levels per stratum.",
          "- `realised.csv` the realised structure of every configuration.",
          "- `results.jsonl` every run; `--mode analyse` rebuilds everything else from it."]
    with open(os.path.join(run_dir, "P4C_screen.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


# ============================================================================
# The sweep's curves: every knob across its range, one line per background
# ============================================================================
CURVE_OUTCOMES = [
    ("collapse", "Flag captured", "either flag: 80% of nodes compromised, or 80% of node value taken out", "C"),
    ("value_flag", "Value flag", "share of runs ended by the value flag (80% of node value out of service)", None),
    ("service_loss", "Service loss", "share of the estate's revenue lost per tick to nodes the attack took out, while the run lasted", None),
    ("data_loss", "Data loss", "share of the estate's data value exfiltrated", None),
    ("defender_loss", "Loss to isolation", "share of revenue lost per tick to nodes the defender isolated", None),
    ("wait", "Wait for the team", "mean ticks a job waited before a responder took it", None),
    ("survival", "Survival", "share of the run for which the estate stays standing (100 = never lost)", "R"),
    ("peak", "Furthest reached", "largest share of the estate compromised at any time", None),
    ("compromise", "Compromise while standing", "average share compromised until the flag or the end", "A"),
    ("impact", "Impact (observed)", "share of node-time observed reconfigured by the attacker, to the flag or the end", None),
    ("excluded", "Defender excluded", "share of nodes under a captured Control Plane at the end", None),
    ("route_entry", "Taken by Initial Access", "share of the estate held at the end that was taken from outside over an Interface", None),
    ("route_conn", "Taken by Lateral Movement", "share of the estate held at the end that was taken node to node", None),
    ("route_chan", "Taken by Channel", "share of the estate held at the end that was taken over a delivery channel", None),
    ("route_ctrl", "Taken by Control Plane", "share of the estate held at the end that was taken through a master controller or trusted authority", None),
    ("masters_held", "Controllers held", "share of controllers in the attacker's hands at the end", None),
    ("harvested", "Harvested", "share of nodes an infostealer captured at any time", None),
]
CURVE_COLOURS = dict(strong=("#2a78d6", "#3987e5"), middle=("#eb6834", "#d95926"),
                     sealed=("#1baf7a", "#199e70"), neutral=("#6250d6", "#9085e9"))


def _level_text(knob: str, level) -> str:
    if isinstance(level, str):
        return level
    v = float(level)
    if v >= 9999:
        return "never"
    lv = CONN_LADDER["chain"] if knob == "conn" else REGISTER[knob][3]
    if knob != "conn" and all(isinstance(x, float) for x in lv) and max(lv) <= 1.0 and knob != "fanout":
        return f"{v * 100:.0f}%"
    return f"{v:g}"


def sweep_table(per: Dict[tuple, dict]) -> List[dict]:
    """One row per attack kind, stratum, background, knob and level, the knob's
    own value in that background included (marked base)."""
    rows = []
    for (kind, b), an in per.items():
        for s in an["strata"]:
            t, g = s["topology"], s["gamma"]
            base_kn = Knobs(topology=t, kind=kind, **POINTS[b])
            cur = [r for r in an["curves"] if r["topology"] == t and r["gamma"] == g]
            byconf = {r["config"]: r for r in cur}
            by_knob: Dict[str, List[dict]] = {}
            for r in cur:
                by_knob.setdefault(r["knob"], []).append(r)
            for knob, rs in by_knob.items():
                for ref in {r["reference"] for r in rs}:
                    grp = [r for r in rs if r["reference"] == ref]
                    if ref == "neutral":
                        base_row, kn = s.get("base", s), base_kn
                    elif ref in byconf:
                        base_row = byconf[ref]
                        other, val = ref.split("=")
                        kn = dataclasses.replace(base_kn, **{other: type(getattr(base_kn, other))(float(val))})
                    else:
                        continue
                    if knob in NEEDS and ref == "neutral":
                        continue      # the helper level of another knob's ladder, not this knob's curve
                    base_level = getattr(kn, knob)
                    pts = [(r["level"], r, False) for r in grp] + [(base_level, base_row, True)]
                    for level, r, is_base in pts:
                        rows.append(dict(kind=kind, topology=t, gamma=g, background=b, knob=knob,
                                         level=level, base=int(is_base),
                                         **{k: float(r.get(k, float("nan"))) for k, *_ in CURVE_OUTCOMES},
                                         **{k: float(r.get(k, float("nan"))) for k in SD_COLS}))
    return rows


SD_COLS = ("flag_sd_wirings", "peak_sd_wirings", "data_loss_sd_wirings")
RANK_ON = ("collapse", "survival", "peak", "compromise", "service_loss", "data_loss", "harvested")
KIND_TEXT = dict(malware="Malware: travels on Connections, spreads unaided, leaves a signature",
                 implant="Implant: arrives by Channel from a compromised supplier, lies dormant, then operated by hand",
                 intrusion="Intrusion: hands-on, uses credentials, leaves no signature",
                 stealer="Infostealer: lands, does not spread, harvests the node and its stored service credentials",
                 campaign="Campaign: stealer payloads first, then an intrusion by the same attacker using what was stolen",
                 mixed="Mixed: every behaviour at once")


def write_curves(run_dir: str, per: Dict[tuple, dict]) -> str:
    rows = sweep_table(per)
    _csv(os.path.join(run_dir, "sweep_curves.csv"), rows)
    kinds = [k for k in KINDS + ("mixed",) if any(kk == k for kk, _b in per)]
    bgs = [b for b in POINTS if any(bb == b for _k, bb in per)]
    noise = {}
    for (kind, b), an in per.items():
        for s in an["strata"]:
            for k in FAMILIES:
                key = (kind, s["topology"], s["gamma"], k)
                noise[key] = max(noise.get(key, 0.0), s[f"noise_{k}"])
    W, H, ML, MR, MT, MB = 196, 104, 26, 8, 8, 18
    pw, ph = W - ML - MR, H - MT - MB

    def panel(knob, outcome, data):
        levels = sorted({_lv(r["level"], knob) for b in data for r in data[b]})
        raw = {}
        for b in data:
            for r in data[b]:
                raw[_lv(r["level"], knob)] = r["level"]
        xi = {v: (ML + (pw * i / (len(levels) - 1) if len(levels) > 1 else pw / 2)) for i, v in enumerate(levels)}
        # every outcome is a share on a 0 to 100 scale except the wait, which is
        # in ticks and takes its own axis (v0.20)
        in_ticks = outcome == "wait"
        top = 1.0
        if in_ticks:
            vals = [r[outcome] for b in data for r in data[b] if np.isfinite(r[outcome])]
            top = max(1.0, float(np.ceil(max(vals)))) if vals else 1.0
        yv = lambda v: MT + ph * (1 - min(max(v, 0.0), top) / top)
        grid = ((0.0, "0"), (top / 2, f"{top / 2:g}"), (top, f"{top:g} ticks")) if in_ticks else ((0.0, "0"), (0.5, "50"), (1.0, "100"))
        o = [f'<svg viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
             f'aria-label="{html_escape(REGISTER[knob][2])}: {outcome}">']
        for gv, lab in grid:
            o.append(f'<line class="grid" x1="{ML}" x2="{W - MR}" y1="{yv(gv):.1f}" y2="{yv(gv):.1f}"/>'
                     f'<text class="tick" x="{ML - 4}" y="{yv(gv) + 3:.1f}" text-anchor="end">{lab}</text>')
        if levels:
            o.append(f'<text class="tick" x="{ML}" y="{H - 4}" text-anchor="start">{_level_text(knob, raw[levels[0]])}</text>')
            o.append(f'<text class="tick" x="{W - MR}" y="{H - 4}" text-anchor="end">{_level_text(knob, raw[levels[-1]])}</text>')
        for b in bgs:
            pts = sorted(((_lv(r["level"], knob), r) for r in data.get(b, []) if np.isfinite(r[outcome])),
                         key=lambda p: p[0])
            if not pts:
                continue
            path = " ".join(f"{'M' if i == 0 else 'L'}{xi[v]:.1f},{yv(r[outcome]):.1f}" for i, (v, r) in enumerate(pts))
            o.append(f'<path class="ln s-{b}" d="{path}"/>')
            for v, r in pts:
                tip = (f"{b} background, {html_escape(REGISTER[knob][2])} = {_level_text(knob, r['level'])}"
                       f"{' (its value in this background)' if r['base'] else ''}: "
                       + (f"{r[outcome]:.1f} ticks" if in_ticks else f"{r[outcome] * 100:.0f}%"))
                cls = "base" if r["base"] else "pt"
                rad = 3.6 if r["base"] else 2.6
                o.append(f'<circle class="{cls} s-{b}" cx="{xi[v]:.1f}" cy="{yv(r[outcome]):.1f}" r="{rad}">'
                         f'<title>{tip}</title></circle>')
        o.append("</svg>")
        return "".join(o)

    # swing of every dial for every kind: the largest change across its range,
    # in any background, in any of the ranking outcomes
    swing: Dict[tuple, dict] = {}
    data_of: Dict[tuple, dict] = {}
    for r in rows:
        data_of.setdefault((r["kind"], r["topology"], r["gamma"], r["knob"]), {}).setdefault(
            r["background"], []).append(r)
    for key, data in data_of.items():
        per_o = {}
        for okey, *_ in CURVE_OUTCOMES:
            best = 0.0
            for b in data:
                vals = [x[okey] for x in data[b] if np.isfinite(x[okey])]
                if len(vals) > 1:
                    best = max(best, max(vals) - min(vals))
            per_o[okey] = best
        swing[key] = per_o
    top_of = lambda key: max(swing[key][o] for o in RANK_ON) if key in swing else float("nan")

    css_light = "".join(f"--s-{b}:{CURVE_COLOURS[b][0]};" for b in CURVE_COLOURS)
    css_dark = "".join(f"--s-{b}:{CURVE_COLOURS[b][1]};" for b in CURVE_COLOURS)
    series_css = "".join(f".ln.s-{b}{{stroke:var(--s-{b})}}.pt.s-{b}{{fill:var(--s-{b})}}"
                         f".base.s-{b}{{stroke:var(--s-{b})}}.sw.s-{b}{{background:var(--s-{b})}}"
                         for b in CURVE_COLOURS)
    L = ["<!doctype html><html lang='en-GB'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width, initial-scale=1'>",
         "<title>Paper 4C sweep curves</title><style>",
         f":root{{--bg:#fcfcfb;--ink:#1f1f1d;--ink2:#5a5a55;--line:#e4e3de;--heat:42,120,214;{css_light}}}",
         f"@media (prefers-color-scheme: dark){{:root{{--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--line:#34342f;--heat:57,135,229;{css_dark}}}}}",
         "body{background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;margin:0;padding:20px 16px 60px}",
         "h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:38px 0 6px}h3{font-size:15px;margin:22px 0 4px}",
         "p{max-width:900px;color:var(--ink2);margin:6px 0}a{color:inherit}",
         ".legend{display:flex;gap:18px;flex-wrap:wrap;margin:12px 0;position:sticky;top:0;background:var(--bg);padding:8px 0;z-index:2;border-bottom:1px solid var(--line)}",
         ".legend span{display:inline-flex;align-items:center;gap:6px}.sw{width:18px;height:3px;border-radius:2px;display:inline-block}",
         ".ring{width:8px;height:8px;border-radius:50%;border:2px solid var(--ink2);display:inline-block}",
         ".wrap{overflow-x:auto}table{border-collapse:collapse}th,td{padding:4px 6px;vertical-align:middle;text-align:left}",
         "th{font-weight:600;font-size:12px;color:var(--ink);border-bottom:1px solid var(--line);max-width:196px}",
         "th small{display:block;font-weight:400;color:var(--ink2)}tr+tr td{border-top:1px solid var(--line)}",
         "td.k{min-width:210px;max-width:240px}td.k b{display:block}td.k small{color:var(--ink2)}",
         "table.mx td.n{text-align:right;font-variant-numeric:tabular-nums;min-width:74px;border-left:2px solid var(--bg)}",
         "table.mx td.l{min-width:300px}table.mx small{color:var(--ink2)}",
         ".grid{stroke:var(--line);stroke-width:1}.tick{fill:var(--ink2);font-size:9.5px}",
         ".ln{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}.pt{stroke:var(--bg);stroke-width:1}",
         ".base{fill:var(--bg);stroke-width:2}", series_css, "</style></head><body>",
         f"<h1>Paper 4C value-range sweep</h1><p>{CODE_VERSION}. Every dial is stepped across its whole "
         "range, one dial at a time, and the outcome is drawn against the dial's value. Each run sends one "
         "kind of attack only. Each line is one background: the position at which the defender's other "
         "operating dials are held while the dial moves. No value is claimed to be typical. Vertical scale "
         "is 0 to 100 per cent in every panel. Hover over a point for its value. The same numbers are in "
         "<code>sweep_curves.csv</code> and <code>sweep_swing.csv</code>. Screening pass on pilot seeds: it "
         "finds which dials matter and is not a confirmatory result.</p>"]
    summary = []
    strata = sorted({(r["topology"], r["gamma"]) for r in rows})
    for (t, g) in strata:
        knobs_here = [k for k in REGISTER if any((kd, t, g, k) in swing for kd in kinds)]
        L.append("<h2>Dial against attack kind</h2><p>Swing: the largest change the dial produces across "
                 "its range, in any background, in the flag, survival, the furthest share reached, "
                 "compromise while standing, observed impact or (for the infostealer) the harvest, in "
                 "percentage points. A blank or small figure is a conditional verdict: the dial may be "
                 "masked by another route, may not apply to that attack profile, or may act only in "
                 "combination. Dials are ordered by their "
                 "largest swing against any kind. A dial that matters against one kind and not another is "
                 "the thing to look for.</p><div class='wrap'><table class='mx'><tr><th>Dial</th>"
                 + "".join(f"<th><a href='#k-{kd}'>{kd.capitalize()}</a></th>" for kd in kinds) + "</tr>")
        order_all = sorted(knobs_here, key=lambda k: -np.nanmax([top_of((kd, t, g, k)) if (kd, t, g, k) in swing
                                                                  else 0.0 for kd in kinds]))
        for knob in order_all:
            layer, who, label, _ = REGISTER[knob]
            cells = []
            for kd in kinds:
                v = top_of((kd, t, g, knob))
                if not np.isfinite(v):
                    cells.append("<td class='n'>-</td>")
                else:
                    cells.append(f"<td class='n' style='background:rgba(var(--heat),{0.75 * min(v, 1.0):.2f})'>"
                                 f"{v * 100:.0f}</td>")
            L.append(f"<tr><td class='l'><b>{html_escape(label)}</b> <small>{layer}, {WHO[who]}</small></td>"
                     + "".join(cells) + "</tr>")
        L.append("</table></div>")
        for kd in kinds:
            L.append(f"<h2 id='k-{kd}'>{html_escape(KIND_TEXT.get(kd, kd))}</h2>")
            nz = [f"{lab.lower()} about {noise[(kd, t, g, fam)] * 100:.0f} points"
                  for _key, lab, _d, fam in CURVE_OUTCOMES if fam and (kd, t, g, fam) in noise]
            if nz:
                L.append("<p>Run-to-run noise (largest across backgrounds): " + "; ".join(nz)
                         + ". A change smaller than that is not distinguishable from no change.</p>")
            L.append("<div class='legend'>" + "".join(
                f"<span><i class='sw s-{b}'></i>{b} background"
                + (f" (dials at {BACKGROUND_POSITIONS[b] * 100:.0f}% of the way from worst to best"
                   + (f"; {BACKGROUND_NOTE[b]}" if b in BACKGROUND_NOTE else "") + ")" if b in BACKGROUND_POSITIONS else "")
                + "</span>" for b in bgs if (kd, b) in per)
                + "<span><i class='ring'></i>the dial's own value in that background</span></div>")
            mine = [k for k in knobs_here if (kd, t, g, k) in swing]
            order = sorted(mine, key=lambda k: -top_of((kd, t, g, k)))
            L.append("<div class='wrap'><table><tr><th>Dial</th>" + "".join(
                f"<th>{lab}<small>{desc}</small></th>" for _k, lab, desc, _f2 in CURVE_OUTCOMES) + "</tr>")
            for knob in order:
                layer, who, label, _ = REGISTER[knob]
                key = (kd, t, g, knob)
                L.append(f"<tr><td class='k'><b>{html_escape(label)}</b><small>{layer} layer, {WHO[who]}; "
                         f"swing {top_of(key) * 100:.0f} points</small></td>"
                         + "".join(f"<td>{panel(knob, okey, data_of[key])}</td>" for okey, *_ in CURVE_OUTCOMES)
                         + "</tr>")
                summary.append(dict(kind=kd, topology=t, gamma=g, knob=knob, label=label, layer=layer,
                                    who=WHO[who], swing=top_of(key),
                                    **{f"swing_{k}": v for k, v in swing[key].items()}))
            L.append("</table></div>")
    L.append("</body></html>")
    _csv(os.path.join(run_dir, "sweep_swing.csv"),
         sorted(summary, key=lambda r: (r["kind"], r["topology"], r["gamma"], -r["swing"])))
    path = os.path.join(run_dir, "P4C_curves.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


def html_escape(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ============================================================================
# Modes
# ============================================================================
def _default_workers() -> int:
    try:
        return max(1, (os.cpu_count() or 2) - 1)
    except Exception:
        return 1


def _pool_iter(fn, tasks, workers):
    """Yield results as they complete (order not preserved)."""
    if workers and workers > 1 and len(tasks) > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for fut in as_completed([ex.submit(fn, t) for t in tasks]):
                yield fut.result()
    else:
        for t in tasks:
            yield fn(t)


def _run_4b(structure, sp, rc, cs, adaptation, init, seed, horizon, engine="4b", mod=None):
    """One E8 episode on the 4B estate, by the embedded 4B engine, by an external
    PhDPaper4B module, or by Engine4C on a one-cluster layout."""
    if engine == "ref":
        return mod._cuspmap_run_one(structure, sp, rc, cs, adaptation, init,
                                    E8["n_estate"], horizon, seed)
    spec, master, src = build_4b(structure, E8["n_estate"], seed)
    spec.deterministic = False
    cfg = cfg_e8(sp, rc, cs, horizon, seed, adaptation)
    if engine == "4c":
        eng = Engine4C(spec, cfg, layout_4b(spec, master, src))
        eng.start(init)
        rec = eng.run()
        return rec.compromised[-1] / max(int(eng.est.sum()), 1)
    eng = Engine4B(spec, cfg, master=master, source=src, source_trusted=True)
    for j in np.flatnonzero(eng.net.external):
        eng.state[j] = COMPROMISED
        eng.comp_ref[j] = 0
    if init == "all":
        mi = eng.master if eng.master is not None else -1
        for j in [int(j) for j in np.flatnonzero(eng.est) if j != mi]:
            eng.state[j] = COMPROMISED
            eng.comp_ref[j] = 0
    eng.atk_reference = 0
    rec = eng.run()
    return rec.compromised[-1] / max(int(eng.est.sum()), 1)


def _gate0b_cell(task):
    structure, sp, rc, seeds, R, horizon = task
    lo, hi = [], []
    for s in seeds:
        for r in range(R):
            rs = s * 1000 + r
            lo.append(_run_4b(structure, sp, rc, E8["strat_cycle"], False, None, rs, horizon, "4c"))
            hi.append(_run_4b(structure, sp, rc, E8["strat_cycle"], False, "all", rs, horizon, "4c"))
    lo_m, hi_m = float(np.mean(lo)), float(np.mean(hi))
    return dict(structure=structure, spread=sp, recovery=rc, lo=lo_m, hi=hi_m,
                bistable=bool(hi_m - lo_m >= E8["tau"] and lo_m <= E8["lo_max"]
                              and hi_m >= E8["hi_min"]))


def mode_gate0(out_root=None, workers=1, ref_path=None, reps=None, quick=False):
    rd = new_run_dir(resolve_run_root(out_root), "gate0")
    L = [f"# Paper 4C Gate 0 ({CODE_VERSION})", ""]
    mod = None
    if ref_path:
        import importlib.util
        sp_ = importlib.util.spec_from_file_location("p4b_reference", ref_path)
        mod = importlib.util.module_from_spec(sp_)
        sys.modules["p4b_reference"] = mod
        sp_.loader.exec_module(mod)
    cases = []
    horizon = 200 if quick else E8["horizon"]
    for st in ("chain", "mesh", "star"):
        for (sp, rc, cs, ad) in [(2, 2, 20, False), (8, 8, 20, False), (8, 32, 20, False),
                                 (32, 16, 20, False), (64, 64, 20, False),
                                 (8, 8, 5, True), (8, 8, 80, True), (2, 16, 20, True)]:
            for init in (None, "all"):
                for seed in (4101000, 4202007):
                    cases.append((st, sp, rc, cs, ad, init, seed))
    bad_emb, bad_ref, worst = 0, 0, 0.0
    for (st, sp, rc, cs, ad, init, seed) in cases:
        a = _run_4b(st, sp, rc, cs, ad, init, seed, horizon, "4c")
        b = _run_4b(st, sp, rc, cs, ad, init, seed, horizon, "4b")
        bad_emb += int(a != b)
        worst = max(worst, abs(a - b))
        if mod is not None:
            c = _run_4b(st, sp, rc, cs, ad, init, seed, horizon, "ref", mod)
            bad_ref += int(a != c)
            worst = max(worst, abs(a - c))
    pass_a = bad_emb == 0 and bad_ref == 0
    L += ["## (a) Engine4C reduces to the 4B engine", "",
          f"{len(cases)} E8 episodes (three estates, both starts, adaptation off and on, "
          f"horizon {horizon}), compared run for run.", "",
          f"- against the embedded PhDPaper4B v0.23 engine: {len(cases) - bad_emb}/{len(cases)} identical",
          (f"- against the external file `{os.path.basename(ref_path)}` "
           f"({getattr(mod, 'CODE_VERSION', '?')}): {len(cases) - bad_ref}/{len(cases)} identical"
           if mod is not None else "- external reference file: not supplied (--ref)"),
          f"- largest difference in final compromised share: {worst:.6f}",
          f"- **{'PASS' if pass_a else 'FAIL'}**", ""]
    print("\n".join(L), flush=True)
    R = reps if reps else (2 if quick else E8["R"])
    tasks = [(st, sp, rc, tuple(E8["seeds"]), R, E8["horizon"])
             for st in ("chain", "mesh", "star") for sp in E8["spread"] for rc in E8["recovery"]]
    print(f"(b) E8 Plane A with Engine4C: {len(tasks)} cells, {len(E8['seeds'])}x{R} runs x 2 "
          f"starts, workers={workers}", flush=True)
    res, t0 = [], time.time()
    for r in _pool_iter(_gate0b_cell, tasks, workers):
        res.append(r)
        if len(res) % 12 == 0 or len(res) == len(tasks):
            print(f"  gate0: {len(res)}/{len(tasks)} cells, {time.time() - t0:.0f}s", flush=True)
    Lb = ["## (b) E8 Plane A reproduced with Engine4C", "",
          f"n={E8['n_estate']}, horizon {E8['horizon']}, seeds {E8['seeds']} x {R} "
          f"(Paper 4B used x {E8['R']}).", "",
          "| estate | bistable spread rows | Paper 4B Table IV | match |", "|---|---|---|---|"]
    pass_b = True
    for st in ("chain", "mesh", "star"):
        rows = sum(1 for sp in E8["spread"]
                   if any(r["bistable"] for r in res if r["structure"] == st and r["spread"] == sp))
        exp = E8["expected_bistable_rows"][st]
        ok = rows == exp
        pass_b = pass_b and ok
        Lb.append(f"| {st} | {rows} of {len(E8['spread'])} | {exp} of 6 | {'yes' if ok else 'NO'} |")
    Lb += ["", f"- **{'PASS' if pass_b else 'FAIL'}**"
           + ("" if R == E8["R"] else f" (at {R} runs per seed block; rerun without --reps or "
              f"--quick for the full E8 budget)"), ""]
    print("\n".join(Lb), flush=True)
    with open(os.path.join(rd, "P4C_gate0.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L + Lb) + "\n")
    _csv(os.path.join(rd, "gate0_planeA.csv"), res)
    write_record(rd, "gate0", dict(gate0a_pass=pass_a, gate0b_pass=pass_b, reps=R,
                                   reference_file=ref_path))
    print(f"written to {rd}")
    return pass_a and pass_b


def _plan(topologies, gammas, steps, knobs, cap_rule="ratio"):
    tasks = build_tasks(topologies, gammas, steps, knobs, cap_rule)
    runs = (len(SCREEN["spread"]) * len(SCREEN["recovery"])
            * len(SCREEN["seeds_a"]) * SCREEN["reps"])
    return tasks, runs


def mode_time(workers=1, steps=5):
    """Time sample runs for each attack kind and background and project the
    smoke test and the full sweep on this machine."""
    print(f"timing ({CODE_VERSION}); one process", flush=True)
    per = {}
    for kd in KINDS:
        for b in BACKGROUND_POSITIONS:
            kn = Knobs(topology="chain", kind=kd, **POINTS[b])
            spec, layout, _ = generate(kn, 0)
            net = _core_build_network(spec, np.random.default_rng(kn.wiring_seed))
            t0, n = time.time(), 0
            for sp in (8, 64):
                for rc in (1, 16, 64):
                    run_one(spec, layout, net, kn, sp, rc, None, 6101000 + n)
                    n += 1
            per[(kd, b)] = (time.time() - t0) / n
        print(f"  {kd:<9} " + ", ".join(f"{b} {per[(kd, b)]:.3f}" for b in BACKGROUND_POSITIONS)
              + " s per run", flush=True)
    for label, smoke in (("smoke test", True), ("full sweep", False)):
        keep = {k: SCREEN[k] for k in SMOKE}
        if smoke:
            SCREEN.update(SMOKE)
        total, ntask = 0.0, 0
        for kd in KINDS:
            for b in (SMOKE_BACKGROUNDS if smoke else BACKGROUND_POSITIONS):
                set_kind(kd)
                set_point(b)
                tasks, runs = _plan(["chain"], [0], 3 if smoke else 99, None)
                total += per[(kd, b)] * runs * len(tasks) * 1.3    # some dial levels run slower
                ntask += len(tasks)
        SCREEN.update(keep)
        set_point("neutral")
        set_kind("mixed")
        print(f"{label}: {ntask} tasks; about {total / 3600:.1f} core-hours, "
              f"{total / 3600 / max(workers, 1) * 60:.0f} minutes on {workers} workers (if the workers scale)")


def mode_plan(steps=5, knobs=None, topologies=None, gammas=None):
    topologies = topologies or SCREEN["topologies"]
    gammas = gammas if gammas is not None else SCREEN["gammas"]
    tasks, runs = _plan(topologies, gammas, steps, knobs)
    print(f"{CODE_VERSION}: ladder screen at {steps} steps per knob")
    for t in topologies:
        for g in gammas:
            d = design(t, g, steps, knobs)
            print(f"  {t} gamma={g}: {len(d) - 1} knob levels")
    print(f"tasks: {len(tasks)} (each = one configuration on one wiring, {runs} runs)")
    print("knobs walked: " + ", ".join(k for k in REGISTER if not knobs or k in knobs))


def mode_screen(out_root=None, workers=1, steps=99, knobs=None, topologies=None, gammas=None,
                run_dir=None, cap_rule="ratio", quiet=False):
    topologies = topologies or SCREEN["topologies"]
    gammas = gammas if gammas is not None else SCREEN["gammas"]
    tasks, runs = _plan(topologies, gammas, steps, knobs, cap_rule)
    rd = run_dir or new_run_dir(resolve_run_root(out_root), "screen")
    done = {r["key"] for r in load_results(rd)}
    todo = [t for t in tasks if task_key(t) not in done]
    with open(os.path.join(rd, "point.txt"), "w", encoding="utf-8") as f:
        f.write(_POINT[0])
    print(f"{CODE_VERSION}: ladder screen, background {_POINT[0]}\n"
          f"run directory {rd}\n"
          f"{len(tasks)} tasks planned, {len(done)} already saved, {len(todo)} to run; "
          f"{runs} runs per task; workers={workers}; capability rule: {cap_rule}\n"
          f"Safe to stop at any time: rerun with --run-dir \"{rd}\" to resume.", flush=True)
    write_record(rd, "screen", dict(steps=steps, knobs=knobs, topologies=topologies, gammas=gammas,
                                    cap_rule=cap_rule, n_tasks=len(tasks), status="running"))
    t0, n = time.time(), 0
    with open(os.path.join(rd, "results.jsonl"), "a", encoding="utf-8") as f:
        for res in _pool_iter(run_task, todo, workers):
            f.write(json.dumps(res, default=_json_default) + "\n")
            f.flush()
            n += 1
            el = time.time() - t0
            eta = el / n * (len(todo) - n)
            print(f"  screen: {n}/{len(todo)} saved ({res['key']}), {el / 60:.0f} min elapsed, "
                  f"about {eta / 60:.0f} min left", flush=True)
    write_record(rd, "screen", dict(steps=steps, knobs=knobs, topologies=topologies, gammas=gammas,
                                    cap_rule=cap_rule, n_tasks=len(tasks), status="complete"))
    mode_analyse(rd, n_planned=len(tasks), quiet=quiet)
    return rd


def mode_analyse(run_dir: str, n_planned=None, quiet=False):
    results = load_results(run_dir)
    if not results:
        print(f"no results in {run_dir}")
        return
    an = analyse_results(results)
    write_screen(run_dir, results, an, n_planned)
    if not quiet:
        print(open(os.path.join(run_dir, "P4C_screen.md"), encoding="utf-8").read())
    print(f"written to {run_dir}")


# The smoke test: the same sweep cut down to run in well under an hour. Three
# levels per knob (the two ends and the middle of each ladder), a smaller grid,
# fewer runs per cell and a smaller neutral ensemble. It exercises every knob,
# every background and the whole report; its numbers are rough.
SMOKE_BACKGROUNDS = ("strong", "middle")
SMOKE = dict(spread=[1, 256], recovery=[8], seeds_a=[6101, 6102, 6103, 6104], seeds_b=[6201, 6202, 6203, 6204],
             neutral_wirings=list(range(6001, 6007)))


def mode_sweep(out_root=None, workers=1, steps=99, knobs=None, topologies=None, gammas=None,
               run_dir=None, cap_rule="ratio", backgrounds=None, smoke=False, kinds=None):
    """The value-range sweep: every knob stepped across its whole ladder, one
    knob at a time, against each background. One sub-directory per background,
    each saved task by task; rerun with --run-dir to resume. Ends by drawing
    the curves."""
    kinds = kinds or list(KINDS)
    backgrounds = backgrounds or (list(SMOKE_BACKGROUNDS) if smoke else list(BACKGROUND_POSITIONS))
    topologies = topologies or ["chain"]
    gammas = gammas if gammas is not None else [0]
    rd = run_dir or new_run_dir(resolve_run_root(out_root), "smoke" if smoke else "sweep")
    sj = os.path.join(rd, "screen.json")
    if os.path.exists(sj):
        saved = json.load(open(sj, encoding="utf-8"))
        SCREEN.update(saved["screen"])
        steps = saved["steps"]
    else:
        if smoke:
            SCREEN.update(SMOKE)
            steps = min(steps, 3)
        with open(sj, "w", encoding="utf-8") as f:
            json.dump(dict(screen={k: SCREEN[k] for k in SMOKE}, steps=steps, smoke=bool(smoke)), f)
    print(f"{CODE_VERSION}: value-range sweep, attack kinds {', '.join(kinds)}; "
          f"backgrounds {', '.join(backgrounds)}; "
          f"topologies {topologies}; governance scopes {gammas}\nsweep directory {rd}", flush=True)
    for kd in kinds:
        for b in backgrounds:
            set_kind(kd)
            set_point(b)
            sub = os.path.join(rd, kd, b)
            os.makedirs(sub, exist_ok=True)
            mode_screen(None, workers, steps, knobs, topologies, gammas, sub, cap_rule, quiet=True)
    mode_curves(rd)
    return rd


# The ablation switches are named for the stage of the model each one removes,
# and each stage is mapped to the ATT&CK tactic of that name. The tactics are
# MITRE's; the ordering, transitions and probabilities are this model's. They
# are interventions on those stages, not removals of a relation class: with
# Initial Access by supplier off, an operator can still capture an internal
# delivery server and push over that Channel.
STAGE_SWITCHES = (("route_sup", "Initial Access by supplier"), ("route_esc", "Privilege Escalation"),
                  ("route_cred", "Credential Access"), ("route_lat", "Lateral Movement"))
ROUTES = STAGE_SWITCHES


def _cells_of(rs: List[dict]) -> List[dict]:
    return [cell["c"] for r in rs for cell in r["cells"]]


def _row_of(rs: List[dict]) -> dict:
    """Means over every run of a configuration, with the spread between
    wirings and between grid cells for the main outcomes."""
    c = _cells_of(rs)
    mean = lambda k: float(np.mean([v for cc in c for v in cc[k]]))
    share = lambda k: float(np.mean([a_ * b_ for cc in c for a_, b_ in zip(cc[k], cc["f"])]))
    tfs = [t for cc in c for t, f_ in zip(cc["tf"], cc["fl"]) if f_]
    per_w = lambda k: [float(np.mean([v for cell in r["cells"] for v in cell["c"][k]])) for r in rs]
    per_cell: Dict[tuple, List[float]] = {}
    for r in rs:
        for cell in r["cells"]:
            per_cell.setdefault((cell["sp"], cell["rc"]), []).extend(cell["c"]["pk"])
    pc = [float(np.mean(v)) for v in per_cell.values()]
    return dict(flag=mean("fl"), value_flag=mean("fv"), survival=mean("sv"), peak=mean("pk"),
                compromise=mean("ar"), excluded=mean("ex"), service_loss=mean("sl"),
                defender_loss=mean("sd"), data_loss=mean("dl"), harvested=mean("hv"),
                time_to_flag=float(np.median(tfs)) if tfs else float("nan"),
                escalations=mean("ne"), escalations_won=mean("nw"), alarms=mean("al"),
                backlog=mean("qm"), wait=mean("qw"),
                by_entry=share("r0"), by_lateral=share("r1"), by_channel=share("r2"),
                by_control_plane=share("r3"),
                flag_sd_wirings=float(np.std(per_w("fl"))), peak_sd_wirings=float(np.std(per_w("pk"))),
                peak_min_cell=min(pc), peak_max_cell=max(pc), n_runs=sum(len(cc["f"]) for cc in c))


def _run_named(rd: str, tasks: List[tuple], workers: int, label: str) -> Dict[str, List[dict]]:
    acc: Dict[str, List[dict]] = {}
    t0 = time.time()
    with open(os.path.join(rd, "results.jsonl"), "a", encoding="utf-8") as f:
        for n_done, res in enumerate(_pool_iter(run_task, tasks, workers), 1):
            f.write(json.dumps(res, default=_json_default) + "\n")
            acc.setdefault(res["name"], []).append(res)
            if n_done % 24 == 0:
                print(f"  {label}: {n_done}/{len(tasks)}, {(time.time() - t0) / 60:.0f} min", flush=True)
    return acc


def mode_ablate(out_root=None, workers=1, full=False, kinds=None, backgrounds=None):
    """Stage-ablation pilot. For each attack kind and background, four stages
    of the model (mapped to ATT&CK tactics) are switched off separately and in every combination, at the neutral
    value of every dial. It shows which stage carries the loss and what remains
    when it is removed."""
    kinds = kinds or list(KINDS)
    backgrounds = backgrounds or list(SMOKE_BACKGROUNDS)
    if not full:
        SCREEN.update(SMOKE)
    S = SCREEN
    rd = new_run_dir(resolve_run_root(out_root), "ablate")
    tasks, meta = [], {}
    nsw = len(STAGE_SWITCHES)
    for kd in kinds:
        for b in backgrounds:
            for bits in range(2 ** nsw):
                off = [name for i, (name, _l) in enumerate(STAGE_SWITCHES) if bits >> i & 1]
                label = "none off" if not off else " + ".join(l for n_, l in STAGE_SWITCHES if n_ in off) + " off"
                for w in S["wirings"]:
                    kn = Knobs(topology="chain", kind=kd, wiring_seed=w, **POINTS[b], **{n_: 0 for n_ in off})
                    name = f"{kd}|{b}|{bits}"
                    meta[name] = (kd, b, bits, label)
                    tasks.append((name, dataclasses.asdict(kn), 0, "a", S["spread"], S["recovery"],
                                  S["seeds_a"], S["reps"]))
    print(f"{CODE_VERSION}: stage-ablation pilot, {len(tasks)} tasks, workers={workers}\nrun directory {rd}",
          flush=True)
    acc = _run_named(rd, tasks, workers, "ablate")
    rows = []
    for name, rs in acc.items():
        kd, b, bits, label = meta[name]
        rows.append(dict(kind=kd, background=b, stages_off=label, bits=bits, **_row_of(rs)))
    rows.sort(key=lambda r: (kinds.index(r["kind"]), backgrounds.index(r["background"]), r["bits"]))
    _csv(os.path.join(rd, "ablation.csv"), rows)
    pc = lambda v: "-" if v != v else f"{v * 100:.0f}%"
    L = [f"# Paper 4C stage-ablation pilot ({CODE_VERSION})", "",
         "Each row switches off the named stages of the model (each mapped to the ATT&CK tactic of that name) "
         "and leaves every dial at its neutral value. "
         "A switch is an intervention on that stage, not the removal of a relation class. "
         f"{len(S['wirings'])} wirings, {len(S['spread'])} x {len(S['recovery'])} grid cells, "
         f"{len(S['seeds_a']) * S['reps']} runs per cell; the runs of a row are not interchangeable "
         "replications (they span wirings and grid cells), so the spread between wirings is given for the flag. "
         "Compromise while standing is not comparable between a row that is lost and one that is not: a lost "
         "run is observed only until the flag. A pilot, not a result.", ""]
    for kd in kinds:
        for b in backgrounds:
            L += [f"## {kd}, {b} background", "",
                  "| stages off | flag | sd between wirings | by value | time to flag | furthest | excluded | "
                  "service loss | data loss | by Initial Access | by Lateral Movement | by Channel | by Control Plane |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
            for r in rows:
                if r["kind"] == kd and r["background"] == b:
                    tf = "-" if r["time_to_flag"] != r["time_to_flag"] else f"{r['time_to_flag']:.0f}"
                    L.append(f"| {r['stages_off']} | {pc(r['flag'])} | {r['flag_sd_wirings'] * 100:.0f} | "
                             f"{pc(r['value_flag'])} | {tf} | {pc(r['peak'])} | {pc(r['excluded'])} | "
                             f"{r['service_loss'] * 100:.1f}% | {r['data_loss'] * 100:.1f}% | {pc(r['by_entry'])} | "
                             f"{pc(r['by_lateral'])} | {pc(r['by_channel'])} | {pc(r['by_control_plane'])} |")
            L.append("")
    with open(os.path.join(rd, "P4C_ablation.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    write_record(rd, "ablate", dict(kinds=kinds, backgrounds=backgrounds, full=bool(full), n_tasks=len(tasks)))
    print(f"written to {rd}")
    return rd


# Paired sweeps for the masking hypothesis. Each dial is swept twice, with
# Credential Access on and off, on seeds and wirings the pilots did not use.
# Masking is shown for a dial only if its effect is small while credential-
# mediated loss decides the outcome and substantial once that is removed.
PAIRED_DIALS = dict(seg_ep=[1, 2, 4, 8], seg_sv=[1, 2, 4, 8], stage_time=[0, 4, 16, 32],
                    coverage=[0.2, 0.6, 1.0], visibility=[0.2, 0.6, 1.0], manual_delay=[0, 2, 8, 16],
                    tac_budget=[1.0, 4.0, 10.0], c2_share=[0.0, 0.4, 0.8, 1.0],
                    ceil_deliv=[20.0, 60.0, 100.0], chan_verify=[0.0, 0.5, 1.0])
PAIRED = dict(spread=[8, 64], recovery=[1, 4, 16, 64], seeds_a=[6301, 6302], wirings=[6021, 6022, 6023])
PAIRED_OUT = ("flag", "survival", "peak", "service_loss", "data_loss")


def mode_paired(out_root=None, workers=1, kinds=None, backgrounds=None, knobs=None):
    kinds = kinds or ["implant", "intrusion"]
    backgrounds = backgrounds or ["middle"]
    dials = {k: v for k, v in PAIRED_DIALS.items() if not knobs or k in knobs}
    S = dict(SCREEN); S.update(PAIRED)
    rd = new_run_dir(resolve_run_root(out_root), "paired")
    tasks, meta = [], {}
    for kd in kinds:
        for b in backgrounds:
            for dial, levels in dials.items():
                for lv in levels:
                    for cred in (1, 0):
                        name = f"{kd}|{b}|{dial}|{lv}|{cred}"
                        meta[name] = (kd, b, dial, lv, cred)
                        for w in S["wirings"]:
                            base = dict(POINTS[b]); base[dial] = type(getattr(Knobs(), dial))(lv)
                            kn = Knobs(topology="chain", kind=kd, wiring_seed=w, route_cred=cred, **base)
                            tasks.append((name, dataclasses.asdict(kn), 0, "a", S["spread"], S["recovery"],
                                          S["seeds_a"], S["reps"]))
    print(f"{CODE_VERSION}: paired sweeps, {len(tasks)} tasks, workers={workers}\nrun directory {rd}", flush=True)
    acc = _run_named(rd, tasks, workers, "paired")
    rows, cellrows = [], []
    for name, rs in acc.items():
        kd, b, dial, lv, cred = meta[name]
        rows.append(dict(kind=kd, background=b, dial=dial, level=lv, credential_access=cred, **_row_of(rs)))
        per: Dict[tuple, Dict[str, list]] = {}
        for r in rs:
            for cell in r["cells"]:
                d_ = per.setdefault((cell["sp"], cell["rc"]), dict(fl=[], pk=[], sv=[], sl=[], dl=[]))
                for k in d_:
                    d_[k] += cell["c"][k]
        for (sp, rc), d_ in sorted(per.items()):
            cellrows.append(dict(kind=kd, background=b, dial=dial, level=lv, credential_access=cred,
                                 spread=sp, recovery=rc, flag=float(np.mean(d_["fl"])),
                                 survival=float(np.mean(d_["sv"])), peak=float(np.mean(d_["pk"])),
                                 service_loss=float(np.mean(d_["sl"])), data_loss=float(np.mean(d_["dl"])),
                                 n_runs=len(d_["fl"])))
    _csv(os.path.join(rd, "paired.csv"), rows)
    _csv(os.path.join(rd, "paired_cells.csv"), cellrows)
    get = lambda kd, b, dial, lv, cred: next(r for r in rows if (r["kind"], r["background"], r["dial"], r["level"],
                                                               r["credential_access"]) == (kd, b, dial, lv, cred))
    L = [f"# Paper 4C paired sweeps for masking ({CODE_VERSION})", "",
         "Each dial is swept with Credential Access on and off, every other dial at the background's value. "
         f"Wirings {S['wirings']}, seeds {S['seeds_a']} (not used by the pilots), "
         f"{len(S['spread'])} x {len(S['recovery'])} grid cells. The range is the largest minus the smallest "
         "mean over the dial's levels. Results by grid cell are in paired_cells.csv; the last columns give, "
         "for the furthest-reached outcome, in how many of the grid cells the range with Credential Access off "
         "exceeds the range with it on. Exploratory: these runs choose what to confirm, they do not confirm it.", ""]
    summ = []
    for kd in kinds:
        for b in backgrounds:
            L += [f"## {kd}, {b} background", ""]
            for dial, levels in dials.items():
                L += [f"### {REGISTER[dial][2] if dial in REGISTER else dial} (`{dial}`)", "",
                      "| level | flag, on | flag, off | time to flag, on | furthest, on | furthest, off | "
                      "service loss, on | service loss, off | data loss, on | data loss, off |",
                      "|---|---|---|---|---|---|---|---|---|---|"]
                for lv in levels:
                    on, off = get(kd, b, dial, lv, 1), get(kd, b, dial, lv, 0)
                    tf = "-" if on["time_to_flag"] != on["time_to_flag"] else f"{on['time_to_flag']:.0f}"
                    L.append(f"| {lv} | {on['flag'] * 100:.0f}% | {off['flag'] * 100:.0f}% | {tf} | "
                             f"{on['peak'] * 100:.0f}% | {off['peak'] * 100:.0f}% | {on['service_loss'] * 100:.1f}% | "
                             f"{off['service_loss'] * 100:.1f}% | {on['data_loss'] * 100:.1f}% | "
                             f"{off['data_loss'] * 100:.1f}% |")
                rng = {}
                for cred in (1, 0):
                    for k in PAIRED_OUT:
                        v = [get(kd, b, dial, lv, cred)[k] for lv in levels]
                        rng[(cred, k)] = max(v) - min(v)
                cells = sorted({(r["spread"], r["recovery"]) for r in cellrows})
                more = 0
                for sp, rc in cells:
                    cr = {}
                    for cred in (1, 0):
                        v = [r["peak"] for r in cellrows if (r["kind"], r["background"], r["dial"], r["credential_access"],
                                                             r["spread"], r["recovery"]) == (kd, b, dial, cred, sp, rc)]
                        cr[cred] = max(v) - min(v)
                    more += int(cr[0] > cr[1] + 0.05)
                noise = float(np.mean([get(kd, b, dial, lv, c_)["peak_sd_wirings"] for lv in levels for c_ in (1, 0)]))
                summ.append(dict(kind=kd, background=b, dial=dial, cells_off_wider=more, n_cells=len(cells),
                                 peak_sd_wirings=noise,
                                 **{f"{k}_range_{'on' if c_ else 'off'}": rng[(c_, k)] for c_ in (1, 0) for k in PAIRED_OUT}))
                L += ["", f"Range over the levels, on then off: flag {rng[(1, 'flag')] * 100:.0f} and "
                      f"{rng[(0, 'flag')] * 100:.0f} points; survival {rng[(1, 'survival')] * 100:.0f} and "
                      f"{rng[(0, 'survival')] * 100:.0f}; furthest {rng[(1, 'peak')] * 100:.0f} and "
                      f"{rng[(0, 'peak')] * 100:.0f}; service loss {rng[(1, 'service_loss')] * 100:.1f} and "
                      f"{rng[(0, 'service_loss')] * 100:.1f}; data loss {rng[(1, 'data_loss')] * 100:.1f} and "
                      f"{rng[(0, 'data_loss')] * 100:.1f}. Spread between wirings in furthest reached: "
                      f"{noise * 100:.0f} points. Wider with Credential Access off in {more} of {len(cells)} grid cells.", ""]
    _csv(os.path.join(rd, "paired_summary.csv"), summ)
    L += ["## Summary: range of each dial's effect, Credential Access on and off", "",
          "| kind | dial | flag on | flag off | survival on | survival off | furthest on | furthest off | "
          "service loss on | service loss off | data loss on | data loss off | wiring spread (furthest) | cells wider off |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in summ:
        p_ = lambda k: f"{r[k] * 100:.0f}"
        L.append(f"| {r['kind']} | {r['dial']} | {p_('flag_range_on')} | {p_('flag_range_off')} | "
                 f"{p_('survival_range_on')} | {p_('survival_range_off')} | {p_('peak_range_on')} | "
                 f"{p_('peak_range_off')} | {r['service_loss_range_on'] * 100:.1f} | "
                 f"{r['service_loss_range_off'] * 100:.1f} | {r['data_loss_range_on'] * 100:.1f} | "
                 f"{r['data_loss_range_off'] * 100:.1f} | {p_('peak_sd_wirings')} | "
                 f"{r['cells_off_wider']} of {r['n_cells']} |")
    with open(os.path.join(rd, "P4C_paired.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    write_record(rd, "paired", dict(kinds=kinds, backgrounds=backgrounds, dials=list(dials), n_tasks=len(tasks)))
    print(f"written to {rd}")
    return rd


# Re-establishing the grid on the frozen model. Every outcome is reported over
# two measurement axes inherited from Paper 4B: spread (the attacker's cadence)
# and recovery (the block cadence). This maps each outcome along both, per
# attack kind and background, against the spread between wirings, so that the
# grid keeps only axes and levels along which something changes.
GRID_MAP = dict(spread=[1, 4, 16, 64, 256], recovery=[1, 4, 16, 64, 256], seeds_a=[6401, 6402],
                wirings=[6031, 6032, 6033])


def mode_grid(out_root=None, workers=1, kinds=None, backgrounds=None):
    kinds = kinds or list(KINDS)
    backgrounds = backgrounds or list(SMOKE_BACKGROUNDS)
    S = dict(SCREEN); S.update(GRID_MAP)
    rd = new_run_dir(resolve_run_root(out_root), "grid")
    tasks = []
    for kd in kinds:
        for b in backgrounds:
            for w in S["wirings"]:
                kn = Knobs(topology="chain", kind=kd, wiring_seed=w, **POINTS[b])
                tasks.append((f"{kd}|{b}", dataclasses.asdict(kn), 0, "a", S["spread"], S["recovery"],
                              S["seeds_a"], S["reps"]))
    print(f"{CODE_VERSION}: grid map, {len(tasks)} tasks, workers={workers}\nrun directory {rd}", flush=True)
    acc = _run_named(rd, tasks, workers, "grid")
    L = [f"# Paper 4C grid map ({CODE_VERSION})", "",
         "Every dial at the background's value. For each axis, the outcome at each level averaged over the other "
         f"axis; {len(S['wirings'])} wirings x {len(S['seeds_a'])} seeds. 'sd' is the spread between wirings of "
         "the overall mean: a range along an axis smaller than about twice that is not distinguishable from it.", ""]
    rows = []
    for name, rs in acc.items():
        kd, b = name.split("|")
        L += [f"## {kd}, {b} background", ""]
        for key, lab in (("fl", "flag"), ("pk", "furthest reached"), ("sl", "service loss"), ("dl", "data loss")):
            overall = [float(np.mean([v for cell in r["cells"] for v in cell["c"][key]])) for r in rs]
            sd = float(np.std(overall))
            line = {}
            for ax, axn in (("sp", "spread"), ("rc", "recovery")):
                lv = sorted({cell[ax] for r in rs for cell in r["cells"]})
                m = [float(np.mean([v for r in rs for cell in r["cells"] if cell[ax] == x for v in cell["c"][key]]))
                     for x in lv]
                line[axn] = (lv, m)
                rows.append(dict(kind=kd, background=b, outcome=lab, axis=axn, range=max(m) - min(m), sd_wirings=sd,
                                 **{f"L{x}": v for x, v in zip(lv, m)}))
            L.append(f"**{lab}** (mean {np.mean(overall) * 100:.0f}%, sd between wirings {sd * 100:.0f}): "
                     + "; ".join(f"by {axn} " + ", ".join(f"{x}: {v * 100:.0f}%" for x, v in zip(*line[axn]))
                                 + f" (range {(max(line[axn][1]) - min(line[axn][1])) * 100:.0f})"
                                 for axn in ("spread", "recovery")))
            L.append("")
    _csv(os.path.join(rd, "grid_map.csv"), rows)
    with open(os.path.join(rd, "P4C_grid.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    write_record(rd, "grid", dict(kinds=kinds, backgrounds=backgrounds, n_tasks=len(tasks)))
    print("\n".join(L))
    print(f"written to {rd}")
    return rd


# ============================================================================
# The confirmatory study of masking (protocol fixed on 13 October, before any
# of its runs). Nothing here is chosen after seeing its own results.
# ============================================================================
CONFIRM = dict(
    background="middle",
    # the headline profile, and one for which the pilots predict no masking
    kinds=["intrusion", "implant", "campaign"],     # v0.4: the campaign (stealer, then intrusion) added
    # dial: (worse level, better level) for the defender, fixed in advance
    pairs=dict(coverage=(0.2, 1.0), manual_delay=(16, 2), visibility=(0.2, 1.0),
               rotate=(0, 2)),                      # v0.4: credential rotation on cleaning, none against the service's
    # how the credential route is closed. "switch" removes the attacker's
    # capability (a mechanism test); the two exposure arms are the defender's
    # own dial: the share of nodes holding a privileged credential
    arms=dict(base={}, switch=dict(route_cred=0), exposure_1=dict(g=0.01), exposure_0=dict(g=0.0)),
    # the three strongest assumptions, each changed once (intrusion, switch arm)
    sensitivity=dict(full_authority=dict(auth_conn=100.0), stay_up=dict(stage_down=0), no_retry=dict(retry=0)),
    spread=[8], recovery=[8],                       # one cell: neither axis moves these kinds (--mode grid)
    wirings=list(range(6601, 6621)),                # v0.4: the draws of the v0.18 final confirmation, for a paired
    seeds=[7401, 7402, 7403, 7404], reps=3,         # comparison of v0.21 with it on the same draws (NOT a fresh confirmation)
    threshold=0.30,                                 # masking is confirmed at 30 points of collapse probability ...
    boot=10000, boot_seed=20261013,                 # ... if the 95% interval over wirings also excludes zero
)
CONFIRM_DRY = dict(wirings=[6401, 6402, 6403, 6404], seeds=[6401], reps=2)
# v0.3 used wirings 6601 to 6620 and seeds 7401 to 7404 for the v0.18 final confirmation.
# v0.4: the final confirmation of v0.21, on wirings and seeds no run of any version has
# used. Run once, after the freeze. --final selects it.
CONFIRM_FINAL = dict(wirings=list(range(6701, 6721)), seeds=[7501, 7502, 7503, 7504], reps=3)


def _boot(vals: np.ndarray, n: int, seed: int) -> Tuple[float, float]:
    rng = np.random.default_rng(seed)
    m = vals[rng.integers(0, len(vals), size=(n, len(vals)))].mean(axis=1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def mode_confirm(out_root=None, workers=1, run_dir=None, dry=False, final=False):
    """The confirmatory study. For each dial, the benefit of the better level
    is the fall in collapse probability from the worse level to the better.
    Masking is the benefit with the credential route closed minus the benefit
    with it open (an interaction), computed wiring by wiring. --quick is a dry
    run on other seeds and wirings that leaves the reserved ones untouched."""
    C = dict(CONFIRM)
    if dry:
        C.update(CONFIRM_DRY)
    elif final:
        C.update(CONFIRM_FINAL)
    b = C["background"]
    rd = run_dir or new_run_dir(resolve_run_root(out_root), "confirm_dry" if dry else ("confirm_final" if final else "confirm_paired"))
    os.makedirs(rd, exist_ok=True)
    cfgs: Dict[str, dict] = {}

    def add(kind, dial, side, arm, sens, extra):
        base = dict(POINTS[b])
        base[dial] = type(getattr(Knobs(), dial))(C["pairs"][dial][0 if side == "worse" else 1])
        base.update(extra)
        cfgs[f"{kind}|{dial}|{side}|{arm}|{sens}"] = dict(kind=kind, kn=base)

    for kind in C["kinds"]:
        for dial in C["pairs"]:
            for side in ("worse", "better"):
                for arm, ex in C["arms"].items():
                    add(kind, dial, side, arm, "rule", ex)
    for sens, sx in C["sensitivity"].items():
        for dial in C["pairs"]:
            for side in ("worse", "better"):
                for arm in ("base", "switch"):
                    add("intrusion", dial, side, arm, sens, dict(C["arms"][arm], **sx))
    tasks = []
    for name, c in cfgs.items():
        for w in C["wirings"]:
            kn = Knobs(topology="chain", kind=c["kind"], wiring_seed=w, **c["kn"])
            tasks.append((name, dataclasses.asdict(kn), 0, "a", tuple(C["spread"]), tuple(C["recovery"]),
                          tuple(C["seeds"]), C["reps"]))
    done = {r["key"]: r for r in load_results(rd)}
    todo = [t for t in tasks if task_key(t) not in done]
    n_runs = len(C["wirings"]) * len(C["seeds"]) * C["reps"]
    print(f"{CODE_VERSION}: confirmatory study{' (DRY RUN)' if dry else ''}, {len(cfgs)} configurations x "
          f"{n_runs} runs, {len(todo)} of {len(tasks)} tasks to run, workers={workers}\nrun directory {rd}", flush=True)
    if todo:
        _run_named(rd, todo, workers, "confirm")
    res = load_results(rd)
    # collapse probability per configuration and wiring
    P: Dict[str, Dict[int, float]] = {}
    R: Dict[str, List[dict]] = {}
    for r in res:
        if r["name"] not in cfgs:
            continue
        c = [cell["c"] for cell in r["cells"]]
        P.setdefault(r["name"], {})[int(r["wiring"])] = float(np.mean([v for cc in c for v in cc["fl"]]))
        R.setdefault(r["name"], []).append(r)
    W = [w for w in C["wirings"] if all(w in P.get(n_, {}) for n_ in cfgs)]
    pv = lambda name: np.array([P[name][w] for w in W])
    ben = lambda kind, dial, arm, sens: pv(f"{kind}|{dial}|worse|{arm}|{sens}") - pv(f"{kind}|{dial}|better|{arm}|{sens}")
    rows = []

    def test(kind, dial, arm, sens):
        b0, b1 = ben(kind, dial, "base", sens), ben(kind, dial, arm, sens)
        inter = b1 - b0
        lo, hi = _boot(inter, C["boot"], C["boot_seed"])
        ok = bool(inter.mean() >= C["threshold"] and lo > 0)
        g = lambda side, a_: float(pv(f"{kind}|{dial}|{side}|{a_}|{sens}").mean())
        rows.append(dict(kind=kind, dial=dial, arm=arm, sensitivity=sens,
                         worse=C["pairs"][dial][0], better=C["pairs"][dial][1],
                         p_worse_open=g("worse", "base"), p_better_open=g("better", "base"),
                         p_worse_closed=g("worse", arm), p_better_closed=g("better", arm),
                         benefit_open=float(b0.mean()), benefit_closed=float(b1.mean()),
                         interaction=float(inter.mean()), ci_low=lo, ci_high=hi,
                         wirings_positive=int((inter > 0).sum()), n_wirings=len(W), confirmed=int(ok)))

    if W:
        for kind in C["kinds"]:
            for dial in C["pairs"]:
                for arm in C["arms"]:
                    if arm != "base":
                        test(kind, dial, arm, "rule")
        for sens in C["sensitivity"]:
            for dial in C["pairs"]:
                test("intrusion", dial, "switch", sens)
    _csv(os.path.join(rd, "confirm.csv"), rows)
    # v0.4: the precursor contrast. The campaign's collapse probability minus the
    # intrusion's, per wiring, in each arm, at each rotation level: what the
    # stealer phase adds to the hands-on intrusion, and whether rotation removes it
    prec = []
    if W and "campaign" in C["kinds"] and "rotate" in C["pairs"]:
        for arm in C["arms"]:
            for side in ("worse", "better"):
                d = pv(f"campaign|rotate|{side}|{arm}|rule") - pv(f"intrusion|rotate|{side}|{arm}|rule")
                lo, hi = _boot(d, C["boot"], C["boot_seed"])
                prec.append(dict(arm=arm, rotate=C["pairs"]["rotate"][0 if side == "worse" else 1],
                                 p_intrusion=float(pv(f"intrusion|rotate|{side}|{arm}|rule").mean()),
                                 p_campaign=float(pv(f"campaign|rotate|{side}|{arm}|rule").mean()),
                                 precursor_effect=float(d.mean()), ci_low=lo, ci_high=hi, n_wirings=len(W)))
        _csv(os.path.join(rd, "precursor.csv"), prec)
    # damage at common observation times, at the background's own settings
    dmg = []
    for kind in C["kinds"]:
        for arm in C["arms"]:
            rs = R.get(f"{kind}|manual_delay|better|{arm}|rule", [])    # every dial at the background's value
            c = [cell["c"] for r in rs for cell in r["cells"]]
            row = dict(kind=kind, arm=arm, n_runs=sum(len(cc["fl"]) for cc in c),
                       flag=float(np.mean([v for cc in c for v in cc["fl"]])) if c else float("nan"))
            tfs = [t for cc in c for t, f_ in zip(cc["tf"], cc["fl"]) if f_]
            row["median_time_to_flag"] = float(np.median(tfs)) if tfs else float("nan")
            for t_ in MARK_TICKS:
                d_ = [v for cc in c for v in cc[f"d{t_}"] if v >= 0]
                s_ = [v for cc in c for v in cc[f"s{t_}"] if v >= 0]
                row[f"standing_at_{t_}"] = len(d_) / max(row["n_runs"], 1)
                row[f"data_loss_at_{t_}"] = float(np.mean(d_)) if d_ else float("nan")
                row[f"service_loss_to_{t_}"] = float(np.mean(s_)) if s_ else float("nan")
            row["data_loss_at_stop"] = float(np.mean([v for cc in c for v in cc["dl"]])) if c else float("nan")
            dmg.append(row)
    _csv(os.path.join(rd, "confirm_damage.csv"), dmg)
    pc = lambda v: "-" if v != v else f"{v * 100:.0f}%"
    pt = lambda v: f"{v * 100:+.0f}"
    arm_text = dict(switch="Credential Access switched off", exposure_1="credential exposure 5% to 1%",
                    exposure_0="credential exposure 5% to 0%")
    tag = " - DRY RUN, not the study" if dry else (" - FINAL confirmation (protocol v0.4, fresh seeds and wirings)" if final
                                                     else " - paired model comparison (protocol v0.4, the v0.18 final draws reused)")
    L = [f"# Paper 4C confirmatory study of masking ({CODE_VERSION})" + tag, "",
         "## Protocol (fixed before the runs)", "",
         f"- Background: {b}. Kinds: {', '.join(C['kinds'])} (the pilots predict masking for the intrusion and none "
         "for the implant; the campaign, v0.4, is the stealer followed by the intrusion of the same attacker).",
         "- Dials and levels (worse, better): " + "; ".join(f"{REGISTER[d][2]} {v[0]} and {v[1]}"
                                                            for d, v in C["pairs"].items()) + ".",
         "- Outcome: collapse probability (either flag). Benefit of a dial: collapse at the worse level minus "
         "collapse at the better level. Masking: the benefit with the credential route closed minus the benefit "
         "with it open, computed wiring by wiring.",
         "- The route is closed three ways: by switching Credential Access off (a mechanism test), and by the "
         "defender's own dial, credential exposure, reduced from 5% of nodes to 1% and to 0%.",
         f"- {len(C['wirings'])} wirings x {len(C['seeds']) * C['reps']} dynamics seeds = {n_runs} independent runs "
         "per configuration. " + ("These wirings and seeds have been used by no run of any version." if final else
                                  "These are the draws of the v0.1 run, reused for a paired comparison between model "
                                  "versions; this is not a fresh confirmation.") +
         " One grid cell (spread 8, recovery 8): the grid map showed neither axis moves these kinds.",
         f"- Decision rule: a dial meets the rule if the point estimate of the interaction is at least "
         f"{C['threshold'] * 100:.0f} points and its 95% interval (bootstrap over wirings, {C['boot']} resamples) "
         "excludes zero. That supports a positive interaction whose estimate exceeds the importance threshold; it does "
         "not establish that the true interaction exceeds it. The nine contrasts per kind are correlated, not nine "
         "independent replications.", ""]
    if not W:
        L += ["No wiring is complete yet; rerun with --run-dir to resume.", ""]
    for kind in C["kinds"] if W else []:
        L += [f"## {kind}", "",
              "| dial | route closed by | collapse, worse to better, route open | the same, route closed | "
              "benefit open | benefit closed | interaction | 95% interval | wirings positive | confirmed |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            if r["kind"] == kind and r["sensitivity"] == "rule":
                L.append(f"| {r['dial']} | {arm_text[r['arm']]} | {pc(r['p_worse_open'])} to {pc(r['p_better_open'])} | "
                         f"{pc(r['p_worse_closed'])} to {pc(r['p_better_closed'])} | {pt(r['benefit_open'])} | "
                         f"{pt(r['benefit_closed'])} | {pt(r['interaction'])} | {pt(r['ci_low'])} to {pt(r['ci_high'])} | "
                         f"{r['wirings_positive']} of {r['n_wirings']} | {'yes' if r['confirmed'] else 'no'} |")
        L.append("")
    if W:
        L += ["## Sensitivity (intrusion, Credential Access switched off)", "",
              "Each row changes one assumption and repeats the test. Full authority: winning a node over a "
              "Connection gives the node's Authority at once, no escalation needed (rule since 18 October: a foothold, "
              "0). No retry: the attacker's footholds are not retried at re-tooling (rule: they are). Stay up: a "
              "won escalation does not take the node out of service (rule: it does). Not part of the decision rule.", "",
              "| assumption changed | dial | collapse, worse to better, route open | route closed | interaction | "
              "95% interval | would confirm |", "|---|---|---|---|---|---|---|"]
        for r in rows:
            if r["sensitivity"] != "rule":
                L.append(f"| {r['sensitivity']} | {r['dial']} | {pc(r['p_worse_open'])} to {pc(r['p_better_open'])} | "
                         f"{pc(r['p_worse_closed'])} to {pc(r['p_better_closed'])} | {pt(r['interaction'])} | "
                         f"{pt(r['ci_low'])} to {pt(r['ci_high'])} | {'yes' if r['confirmed'] else 'no'} |")
        if prec:
            L += ["## The precursor: campaign against intrusion (v0.4)", "",
                  "The campaign's collapse probability minus the intrusion's on the same wirings and seeds, with every other dial "
                  "at the background's value, at each rotation level. A positive effect is what the stealer phase adds; the "
                  "rotation rows show whether rotating credentials on cleaning removes it.", "",
                  "| route | rotation | intrusion | campaign | precursor effect | 95% interval |", "|---|---|---|---|---|---|"]
            for r in prec:
                L.append(f"| {dict(base='open', **arm_text)[r['arm']]} | {r['rotate']} | {pc(r['p_intrusion'])} | {pc(r['p_campaign'])} | "
                         f"{pt(r['precursor_effect'])} | {pt(r['ci_low'])} to {pt(r['ci_high'])} |")
            L.append("")
        L += ["", "## Damage at common observation times (background settings)", "",
              "Loss before the stopping event is not comparable between a run that is lost early and one that "
              "stands for the whole horizon. These columns compare runs at the same hour, among the runs still "
              "standing then. Data loss is the share of data value exfiltrated by that hour; service loss is the "
              "share of revenue lost per hour up to it.", "",
              "| kind | route | collapse | median hour of the flag | standing at 24 / 72 / 168 | "
              "data loss at 24 / 72 / 168 | service loss to 24 / 72 / 168 | data loss at the stop |",
              "|---|---|---|---|---|---|---|---|"]
        arm_name = dict(base="open", **arm_text)
        for r in dmg:
            tf = "-" if r["median_time_to_flag"] != r["median_time_to_flag"] else f"{r['median_time_to_flag']:.0f}"
            tri = lambda k: " / ".join(pc(r[f"{k}{t_}"]) for t_ in MARK_TICKS)
            L.append(f"| {r['kind']} | {arm_name[r['arm']]} | {pc(r['flag'])} | {tf} | {tri('standing_at_')} | "
                     f"{tri('data_loss_at_')} | {tri('service_loss_to_')} | {pc(r['data_loss_at_stop'])} |")
        L.append("")
    with open(os.path.join(rd, "P4C_confirm.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    write_record(rd, "confirm", dict(protocol={k: v for k, v in C.items()}, dry=bool(dry), final=bool(final), n_tasks=len(tasks),
                                     complete_wirings=len(W)))
    print("\n".join(L))
    print(f"written to {rd}")
    return rd


# ============================================================================
# The exposure drill (protocol fixed on 18 October, before any of its runs).
# The confirmatory study found that credential exposure at 1 per cent of nodes
# (one holder for each of six services) loses the estate as surely as 5 per
# cent, and only 0 closes the route. The drill scales exposure UP by count
# from zero, with no rounding, to separate three readings: how many exposed
# credentials are enough; which service's credential; and whether the loss is
# quick or merely certain in time. Prediction recorded before the data: device
# management alone is enough (it reaches all 80 endpoints, the flag is 80 per
# cent); one Active Directory controller alone reaches 78 and needs two more
# nodes by hand, so it is slower; a hypervisor (14 or 6 servers), a console or
# DNS alone are not enough.
# ============================================================================
DRILL = dict(
    kind="intrusion", background="middle",
    counts=[0, 1, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 50, 100, 200, 400],   # part A: total exposed credentials, any
                                                         # service; dense below 6 (the old 1 per cent), up to the old 100 per cent (about 400)
    services=["ad", "mdm", "hv", "hvc", "edr", "dns"],   # part B: one credential, for this service only
    sizes=[50, 100, 200], size_counts=[1, 3],            # part C: size by count
    campaign_counts=[0, 1, 2, 3, 4, 5, 6, 8, 10, 20],    # part D (v0.21): the campaign kind at these counts, against part A
    spread=[8], recovery=[8],
    wirings=list(range(6501, 6521)), seeds=[7101, 7201, 7202, 7301], reps=3,
    week=168,                                            # collapse within a week, as well as ever
    boot=10000, boot_seed=20261018,
)
DRILL_DRY = dict(wirings=[6401, 6402, 6403, 6404], seeds=[6401], reps=2)


def mode_drill(out_root=None, workers=1, run_dir=None, dry=False):
    """The exposure drill. Part A: exposure by count. Part B: one credential,
    one service. Part C: size by count."""
    D = dict(DRILL)
    if dry:
        D.update(DRILL_DRY)
    b = D["background"]
    rd = run_dir or new_run_dir(resolve_run_root(out_root), "drill_dry" if dry else "drill")
    os.makedirs(rd, exist_ok=True)
    cfgs: Dict[str, dict] = {}
    for n in D["counts"]:
        cfgs[f"A|{n}"] = dict(cred_total=n)
    for sv in D["services"]:
        cfgs[f"B|{sv}"] = dict(cred_total=1, cred_only=sv)
    for sz in D["sizes"]:
        for n in D["size_counts"]:
            cfgs[f"C|{sz}|{n}"] = dict(cred_total=n, size=sz)
    for n in D.get("campaign_counts", []):
        cfgs[f"D|{n}"] = dict(cred_total=n, kind="campaign")
    tasks = []
    for name, extra in cfgs.items():
        for w in D["wirings"]:
            ex = dict(extra)
            kd = ex.pop("kind", D["kind"])
            kn = Knobs(topology="chain", kind=kd, wiring_seed=w, **dict(POINTS[b], **ex))
            tasks.append((name, dataclasses.asdict(kn), 0, "a", tuple(D["spread"]), tuple(D["recovery"]),
                          tuple(D["seeds"]), D["reps"]))
    done = {r["key"]: r for r in load_results(rd)}
    todo = [t for t in tasks if task_key(t) not in done]
    n_runs = len(D["wirings"]) * len(D["seeds"]) * D["reps"]
    print(f"{CODE_VERSION}: exposure drill{' (DRY RUN)' if dry else ''}, {len(cfgs)} configurations x {n_runs} runs, "
          f"{len(todo)} of {len(tasks)} tasks to run, workers={workers}\nrun directory {rd}", flush=True)
    if todo:
        _run_named(rd, todo, workers, "drill")
    res = [r for r in load_results(rd) if r["name"] in cfgs]
    acc: Dict[str, List[dict]] = {}
    for r in res:
        acc.setdefault(r["name"], []).append(r)
    wk = int(D["week"])

    def row(name):
        rs = acc.get(name, [])
        c = [cell["c"] for r in rs for cell in r["cells"]]
        fl = np.array([v for cc in c for v in cc["fl"]], dtype=float)
        tf = np.array([v for cc in c for v in cc["tf"]], dtype=float)
        pk = np.array([v for cc in c for v in cc["pk"]], dtype=float)
        ex = np.array([v for cc in c for v in cc["ex"]], dtype=float)
        nt = np.array([v for cc in c for v in cc["nt"]], dtype=float)
        # collapse conditional on the number of Control Planes actually taken
        by_taken = {}
        for k_ in sorted(set(nt.astype(int).tolist())):
            m_ = nt == k_
            by_taken[int(k_)] = (float(fl[m_].mean()), int(m_.sum()))
        per_w = np.array([float(np.mean([v for cell in r["cells"] for v in cell["c"]["fl"]])) for r in rs])
        lo, hi = _boot(per_w, D["boot"], D["boot_seed"]) if len(per_w) > 1 else (float("nan"), float("nan"))
        week = ((tf >= 0) & (tf <= wk)).mean() if fl.size else float("nan")
        lost = tf[tf >= 0]
        # realised exposure, from the first wiring's structure
        return dict(n_runs=int(fl.size), collapse=float(fl.mean()) if fl.size else float("nan"), ci_low=lo, ci_high=hi,
                    collapse_week=float(week), median_tf=float(np.median(lost)) if lost.size else float("nan"),
                    p90_tf=float(np.percentile(lost, 90)) if lost.size else float("nan"),
                    peak=float(pk.mean()) if pk.size else float("nan"), excluded=float(ex.mean()) if ex.size else float("nan"),
                    holders=float(np.mean([r["realised"]["credential_holdings_per_node"] * r["realised"]["n"] for r in rs])) if rs else float("nan"),
                    taken_mean=float(nt.mean()) if nt.size else float("nan"),
                    taken_any=float((nt > 0).mean()) if nt.size else float("nan"),
                    by_taken=by_taken)
    rows = []
    for name in cfgs:
        rows.append(dict(config=name, **cfgs[name], **row(name)))
    _csv(os.path.join(rd, "drill.csv"), [{k: v for k, v in r.items() if k != "by_taken"} for r in rows])
    # exposure, compromise, collapse: collapse conditional on Control Planes taken, pooled over Part A
    pool: Dict[int, List[int]] = {}
    for r in rows:
        if r["config"].startswith("A|"):
            for k_, (p_, n_) in r["by_taken"].items():
                pool.setdefault(k_, [0, 0])
                pool[k_][0] += int(round(p_ * n_)); pool[k_][1] += n_
    pc = lambda v: "-" if v != v else f"{v * 100:.0f}%"
    tk = lambda v: "-" if v != v else f"{v:.0f}"
    get = lambda name: next(r for r in rows if r["config"] == name)
    L = [f"# Paper 4C exposure drill ({CODE_VERSION})" + (" - DRY RUN, not the study" if dry else ""), "",
         "## Protocol (fixed before the runs)", "",
         f"- Kind {D['kind']}, {b} background, every other dial at the background's value. Exposure is set as an "
         "absolute count of privileged credential placements in the estate, scaling up from zero, with no rounding; each "
         "placement is one service's credential on one node, the service drawn at random among those allowed and the node "
         "from that service's own population. Two placements for the same service are two nodes holding that service's "
         "credential, not two distinct secrets.",
         f"- Part A: {D['counts']} credentials, any service. Part B: one credential, one service only, for each of "
         f"{D['services']}. Part C: {D['size_counts']} credentials at estate sizes {D['sizes']}.",
         f"- {len(D['wirings'])} wirings x {len(D['seeds']) * D['reps']} seeds = {n_runs} runs per configuration; "
         "the draws of the v0.1 confirmatory run, so the drill is a paired comparison with it and with its own v0.1, "
         "not an independent confirmation.",
         f"- Outcomes: collapse within the 600-tick horizon (95% interval by bootstrap over wirings), collapse within {wk} ticks, "
         "median and 90th percentile tick of the flag among lost runs, furthest reached, defender excluded.",
         "- Prediction recorded before the data (Part B): device management alone is enough; one Active Directory "
         "controller alone is enough but slower; a hypervisor, a console or DNS alone is not.", "",
         "## Part A: how many exposed credentials", "",
         "| credentials exposed | lost within 600 ticks | 95% interval | lost within 168 ticks | median tick | 90th pct tick | furthest | excluded |",
         "|---|---|---|---|---|---|---|---|"]
    for n in D["counts"]:
        r = get(f"A|{n}")
        L.append(f"| {n} | {pc(r['collapse'])} | {pc(r['ci_low'])} to {pc(r['ci_high'])} | {pc(r['collapse_week'])} | "
                 f"{tk(r['median_tf'])} | {tk(r['p90_tf'])} | {pc(r['peak'])} | {pc(r['excluded'])} |")
    def smallest(pth):
        for n in D["counts"]:
            r = get(f"A|{n}")
            if r["collapse"] >= pth:
                return (f"{n} (estimated collapse at that count {r['collapse'] * 100:.0f}%, 95% interval for that "
                        f"probability {r['ci_low'] * 100:.0f} to {r['ci_high'] * 100:.0f}; not an interval for the threshold itself)")
        return "not reached"
    L += ["", "### Exposure-based brittleness summary (Part A)", "",
          "Structural brittleness is characterised by the probability and timing of estate collapse as privileged exposure "
          "increases, under the specified attack and defence conditions. The summary below is the smallest tested exposure "
          "count at which estimated collapse within 600 ticks reaches a preselected probability. The interval given is the "
          "bootstrap interval for the collapse probability at that count, not an uncertainty interval for the threshold "
          "exposure, which is bounded only by the tested counts on either side. The whole curve above remains the "
          "measure, since a single threshold conceals differences between services and attack profiles. Exposed credentials "
          "still have to be discovered and used, so this is an exposure-based measure; the compromise table below gives the "
          "collapse probability once they have been.", "",
          f"- smallest exposure with collapse at least 50%: {smallest(0.5)}",
          f"- smallest exposure with collapse at least 90%: {smallest(0.9)}", ""]
    L += ["", "### Exposure, compromise, collapse (Part A pooled)", "",
          "Exposure is what the dial sets; compromise is the number of Control Planes the attacker actually took in a run; "
          "collapse is the flag. Runs are grouped by Control Planes taken, whatever the exposure that produced them.", "",
          "| Control Planes taken | runs | lost within 600 ticks |", "|---|---|---|"]
    for k_ in sorted(pool):
        L.append(f"| {k_} | {pool[k_][1]} | {pool[k_][0] / max(pool[k_][1], 1) * 100:.0f}% |")
    L += ["", "| credentials exposed | mean Control Planes taken | runs with any taken |", "|---|---|---|"]
    for n in D["counts"]:
        r = get(f"A|{n}")
        L.append(f"| {n} | {r['taken_mean']:.2f} | {pc(r['taken_any'])} |")
    L += ["", "## Part B: one credential, which service", "",
          "| service | lost within 600 ticks | 95% interval | lost within 168 ticks | median tick | 90th pct tick | furthest | excluded |",
          "|---|---|---|---|---|---|---|---|"]
    names = dict(ad="Active Directory (one controller)", mdm="Device management", hv="Hypervisor (on-premises)",
                 hvc="Cloud provider's hypervisor", edr="Endpoint detection console (one)", dns="DNS")
    for sv in D["services"]:
        r = get(f"B|{sv}")
        L.append(f"| {names[sv]} | {pc(r['collapse'])} | {pc(r['ci_low'])} to {pc(r['ci_high'])} | {pc(r['collapse_week'])} | "
                 f"{tk(r['median_tf'])} | {tk(r['p90_tf'])} | {pc(r['peak'])} | {pc(r['excluded'])} |")
    L += ["", "## Part C: estate size by count", "",
          "| size | credentials exposed | lost within 600 ticks | 95% interval | lost within 168 ticks | median tick | furthest |", "|---|---|---|---|---|---|---|"]
    for sz in D["sizes"]:
        for n in D["size_counts"]:
            r = get(f"C|{sz}|{n}")
            L.append(f"| {sz} | {n} | {pc(r['collapse'])} | {pc(r['ci_low'])} to {pc(r['ci_high'])} | "
                     f"{pc(r['collapse_week'])} | {tk(r['median_tf'])} | {pc(r['peak'])} |")
    if D.get("campaign_counts"):
        L += ["", "## Part D: the campaign against the intrusion (v0.21)", "",
              "The campaign sends stealer payloads for the handoff period and then intrusion payloads from the same attacker, "
              "which use the service credentials the stealers took. Rotation at the background's setting (the cleaned node's "
              "credentials rotated). The intrusion columns are Part A at the same count.", "",
              "| credentials exposed | intrusion lost | campaign lost | 95% interval | campaign median tick | intrusion median tick |",
              "|---|---|---|---|---|---|"]
        for n in D["campaign_counts"]:
            r = get(f"D|{n}"); a_ = get(f"A|{n}")
            L.append(f"| {n} | {pc(a_['collapse'])} | {pc(r['collapse'])} | {pc(r['ci_low'])} to {pc(r['ci_high'])} | "
                     f"{tk(r['median_tf'])} | {tk(a_['median_tf'])} |")
    L.append("")
    with open(os.path.join(rd, "P4C_drill.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    write_record(rd, "drill", dict(protocol=D, dry=bool(dry), n_tasks=len(tasks)))
    print("\n".join(L))
    print(f"written to {rd}")
    return rd


def mode_curves(run_dir: str):
    sj = os.path.join(run_dir, "screen.json")
    if os.path.exists(sj):
        SCREEN.update(json.load(open(sj, encoding="utf-8"))["screen"])
    subs = [(kd, b) for kd in KINDS + ("mixed",) for b in POINTS
            if os.path.exists(os.path.join(run_dir, kd, b, "results.jsonl"))]
    if not subs:
        print(f"no attack-kind and background sub-directories with results in {run_dir}")
        return
    per = {}
    for kd, b in subs:
        set_kind(kd)
        set_point(b)
        res = load_results(os.path.join(run_dir, kd, b))
        if res:
            an = analyse_results(res)
            if an["strata"]:
                per[(kd, b)] = an
    path = write_curves(run_dir, per)
    print(f"curves written to {path}")


# ============================================================================
# Self-test
# ============================================================================
def mode_selftest() -> bool:
    ok_all = True

    def check(name, cond, detail=""):
        nonlocal ok_all
        ok_all = ok_all and bool(cond)
        print(f"  [{'ok' if cond else 'FAIL'}] {name}" + (f": {detail}" if detail else ""), flush=True)

    print(f"{CODE_VERSION} self-test; model digest {MODEL_DIGEST[:16]}, same model as frozen v0.18: {MODEL_DIGEST == MODEL_DIGEST_V018}")
    check("frozen core hashes match the freeze record", all(_FREEZE_REPORT.values()))
    rel = lambda s: [(r.supplier, r.receiver, r.relation_class.value) for r in s.relations]
    for t in ("chain",):
        N = Knobs(topology=t)
        s0, l0, b0 = generate(N, 0)
        s1, l1, b1 = generate(N, 1)
        check(f"{t}: identical wiring in both scopes", rel(s0) == rel(s1))
        check(f"{t}: deterministic in the wiring seed", rel(generate(N, 0)[0]) == rel(s0))
        r0 = realised(N, b0)
        for knob, lv in (("fanout", 1.0), ("inequality", 3.0)):
            kk = dataclasses.replace(N, **{knob: lv})
            rk = realised(kk, generate(kk, 0)[2])
            check(f"{t}: {knob} is count-matched",
                  abs(rk["n_directed_supply"] - r0["n_directed_supply"]) <= 0.05 * r0["n_directed_supply"]
                  and rk["conn_degree_within"] == r0["conn_degree_within"])
        kk = dataclasses.replace(N, g=1.0)
        rg = realised(kk, generate(kk, 0)[2])
        check(f"{t}: changing g leaves the other wiring untouched",
              all(rg[k] == r0[k] for k in r0 if k not in ("credential_holdings_per_node",)))
        net = _core_build_network(s1, np.random.default_rng(1))
        check(f"{t}: every node has all three corners, natively or by supply",
              all(net.table.structural_capability(n_.id) for n_ in s1.nodes))
    # every ladder level of every knob builds a valid estate
    bad = []
    for t in SCREEN["topologies"]:
        for c in design(t, 1, 99):
            try:
                generate(c["kn"], 1)
            except Exception as e:      # noqa: BLE001
                bad.append(f"{t} {c['name']}: {e}")
    check("every knob level builds a valid estate", not bad, "; ".join(bad[:3]))
    # engine reduction (short horizon)
    bad = 0
    for st in ("chain", "mesh", "star"):
        for ad in (False, True):
            for init in (None, "all"):
                a = _run_4b(st, 8, 8, 20, ad, init, 4101000, 150, "4c")
                b = _run_4b(st, 8, 8, 20, ad, init, 4101000, 150, "4b")
                bad += int(a != b)
    check("Engine4C equals Engine4B on the 4B estates (12 episodes)", bad == 0)
    # the neutral knob values are the 4B behaviour on a 4C estate
    N = Knobs(topology="mesh")
    spec, layout, _ = generate(N, 1)
    tmpl = _core_build_network(spec, np.random.default_rng(0))
    cfg = cfg_e8(8, 8, 20, 150, 6101000, False)
    e1 = Engine4C(spec, cfg, layout, net=net_for_seed(tmpl, 6101000)); e1.start(None); e1.run()
    e2 = Engine4C(spec, cfg, layout); e2.start(None); e2.run()
    check("reused network gives the same run as a fresh build", e1.outcome() == e2.outcome())
    N4 = dataclasses.replace(N, auto_clean=0, rebuild_time=0, priority=0, manual_scope=0,
                             manual_delay=0, master_rebuild=-1, retool_fix=0,
                             flag=0.0, payload=0, node_reconf=-1, reconf_time=0, repl_delay=-1,
                             ctl_link=0, hand_delay=0, stage_time=0, ext_bad=1.0,
                             stages=0, queue=0, c2_share=1.0, flag_value=0.0)
    e3 = Engine4C(spec, make_cfg(N4, 8, 8, 6101000), layout, opts=make_opts(N4))
    e3.cfg.horizon = 150; e3.start(None); e3.run()
    check("with two-track recovery off, the knob values reproduce the 4B engine settings",
          e3.outcome() == e2.outcome())
    # two-track recovery
    e4 = Engine4C(spec, make_cfg(N, 64, 8, 6101000), layout, opts=make_opts(N))
    e4.cfg.horizon = 200; e4.start("all"); e4.run()
    check("a rebuilt node rejoins the estate (nothing left isolated at rest or mid-rebuild only)",
          int(e4.isolated.sum()) == sum(1 for q in e4._rebuilding for _, j in q
                                        if j not in e4._master_set))
    check("a captured master is never isolated or reset, only rebuilt",
          not any(e4.isolated[m] for m in e4.masters))
    # manual response delay
    Nd = dataclasses.replace(N, manual_delay=20, auto_clean=0, master_rebuild=-1, coverage=0.0, ext_share=0.4,
                             dormant_share=0.0)
    spd, layd, _ = generate(Nd, 0)
    e6 = Engine4C(spd, make_cfg(Nd, 8, 8, 6101000), layd, opts=make_opts(Nd))
    e6.cfg.horizon = 19; e6.start(None); e6.run()
    check("the team does not act before the manual response delay has passed",
          int(e6.isolated.sum()) == 0 and int(e6._compromised_mask()[e6.all_mask].sum()) > 0)
    check("the manual track takes control-plane nodes first",
          all(e4._tier[m] == 0 for m in e4.masters))
    # a supplied corner is lost when its only supplier relation is cut
    Nx = Knobs(topology="chain", redundancy=1, supplied_x=0.5, chan=0.0)
    spec, layout, built = generate(Nx, 0)
    e = Engine4C(spec, cfg_e8(8, 8, 20, 10, 1, True), layout)
    j = e.net.index[built["no_x"][0]]
    had = e._has_X(j)
    for i in list(e._sup[CHANNEL].get(j, ())):
        e._disable_relation(CHANNEL, i, j)
    check("cutting a sole Channel removes the supplied Execution Pathway", had and not e._has_X(j))
    # theta
    Nt = Knobs(topology="chain", redundancy=3)
    spec, layout, _ = generate(Nt, 0)
    e = Engine4C(spec, cfg_e8(8, 8, 20, 10, 1, False), layout, opts=Opts(theta="all"))
    j = next(j for j, s in e._sup[CHANNEL].items() if len(s) >= 2)
    s = e._sup[CHANNEL][j]
    e.state[s[0]] = COMPROMISED
    part = e._theta_ok(j, CHANNEL)
    for i in s:
        e.state[i] = COMPROMISED
    check("theta=all refuses a delivery until every supplier is compromised",
          (not part) and e._theta_ok(j, CHANNEL))
    # the knobs that were inert in 4B now act
    Nc = Knobs(topology="chain", iface_closed=0.4)
    spec, layout, built = generate(Nc, 0)
    e = Engine4C(spec, make_cfg(Nc, 8, 128, 1), layout, opts=make_opts(Nc))
    e.cfg.horizon = 200; e.start(None); e.run()
    closed_idx = [e.net.index[i] for i in built["closed"]]
    check("no entry point has a closed interface", not set(built["closed"]) & set(built["entries"]))
    Nl = Knobs(topology="chain", detect_latency=6)
    spec, layout, _ = generate(Nl, 0)
    e = Engine4C(spec, make_cfg(Nl, 8, 8, 1), layout, opts=make_opts(Nl))
    e.start(None)
    j = int(e.cluster_nodes[0][3])
    e.state[j] = COMPROMISED; e._tick = 10; e._comp_tick[j] = 8
    young = bool(e._picture(e.domains[0])[j])
    e._tick = 14
    check("a new compromise is unseen until the detection latency has passed",
          (not young) and bool(e._picture(e.domains[0])[j]))
    Nb = Knobs(topology="chain", visibility=0.5, blind_delay=25)
    spec, layout, built = generate(Nb, 0)
    e = Engine4C(spec, make_cfg(Nb, 8, 8, 1), layout, opts=make_opts(Nb))
    e.start(None)
    j = e.net.index[built["unseen"][0]]
    e.state[j] = COMPROMISED; e._comp_tick[j] = 1; e._tick = 10
    hidden = not bool(e._picture(e.domains[0])[j])
    e._tick = 30
    check("an unseen node's compromise is found after the blind-spot delay",
          hidden and bool(e._picture(e.domains[0])[j]))
    def quick(kn, sp=8, rc=16, n=6):
        spec, layout, _ = generate(kn, 0)
        tm = _core_build_network(spec, np.random.default_rng(0))
        return float(np.mean([run_one(spec, layout, tm, dataclasses.replace(kn, horizon=300),
                                      sp, rc, None, 6101000 + i)["ar"] for i in range(n)]))
    base = Knobs(topology="mesh", def_cap=20.0, flag=0.0)
    weak, strong = quick(dataclasses.replace(base, atk_cap=10.0)), quick(dataclasses.replace(base, atk_cap=30.0))
    check("a more capable attacker compromises more", strong > weak, f"{weak:.2f} vs {strong:.2f}")
    drift = quick(dataclasses.replace(base, def_cap=60.0, cap_drift=3.0), n=16)
    still = quick(dataclasses.replace(base, def_cap=60.0), n=16)
    check("security drift raises compromise over a run", drift > still, f"{still:.2f} vs {drift:.2f}")
    Nr = Knobs(topology="chain")
    spec, layout, _ = generate(Nr, 0)
    e = Engine4C(spec, make_cfg(Nr, 8, 8, 1), layout, opts=make_opts(Nr))
    hits = np.mean([e._success() for _ in range(4000)])
    check("at the neutral capabilities (20 against 80) a defender action works 4 times in 5",
          abs(hits - 0.8) < 0.03, f"{hits:.3f}")
    Ne = dataclasses.replace(Nr, atk_cap=50.0, def_cap=50.0)
    e = Engine4C(spec, make_cfg(Ne, 8, 8, 1), layout, opts=make_opts(Ne))
    hits = np.mean([e._success() for _ in range(4000)])
    check("evenly matched capabilities give an even chance", abs(hits - 0.5) < 0.03, f"{hits:.3f}")
    Nc2 = dataclasses.replace(Nr, atk_cap=60.0, def_cap=50.0, cap_rule="cutoff")
    e = Engine4C(spec, make_cfg(Nc2, 8, 8, 1), layout, opts=make_opts(Nc2))
    check("under the cut-off rule the control fails once the attacker is ahead",
          not any(e._success() for _ in range(200)))
    Nm = Knobs(topology="chain", ext_bad=0.0)      # third parties sound unless a check says otherwise
    spec, layout, _ = generate(Nm, 0)
    e = Engine4C(spec, make_cfg(Nm, 8, 8, 1), layout, opts=make_opts(Nm))
    e.start(None)
    j = int(e.cluster_nodes[0][2]); m0 = e.masters_of[0][0]
    ok1 = e._auto_available(j)
    e.state[m0] = COMPROMISED
    check("automation covers a node only while its master is clean; then it is the team's",
          ok1 and not e._auto_available(j) and not e._auto_available(m0))
    # ---- v0.9: zones, master controllers, the flag ------------------------------
    def fresh(kn, sp=8, rc=8, seed=1):
        sp_, lay_, _ = generate(kn, 0)
        e_ = Engine4C(sp_, make_cfg(kn, sp, rc, seed), lay_, opts=make_opts(kn))
        e_.start(None)
        return e_
    e = fresh(Nm)
    ty = layout["types"]
    check("the estate has endpoint segments, remote endpoints, server segments and a cloud",
          ty == ["ep", "ep", "rem", "sv", "sv", "cloud"], str(ty))
    check("every group has an endpoint detection console; Active Directory covers the internal "
          "endpoints and on-premises servers only; DNS, two hypervisors and device management exist",
          all(len(ms) == (2 if ty[k] in ("ep", "sv") else 1) for k, ms in enumerate(e.masters_of))
          and e._dns >= 0 and layout["estate_masters"] == ["hv", "hvc", "mdm"])
    grp = lambda k: [x for x in e.cluster_nodes[k].tolist() if x != e._dns]
    deg_in = lambda k: [len([y for y in e.adj[CONNECTION].get(x, ()) if y in set(grp(k))]) for x in grp(k)]
    check("in a segment every endpoint reaches every other, and remote endpoints reach none of their own",
          min(deg_in(1)) == len(grp(1)) - 1 and max(deg_in(2)) == 0)
    ext_ix = set(e._ext)
    check("external parties are never connected to one another, or to anything by a Connection",
          all(not e.adj[CONNECTION].get(x) for x in ext_ix))
    def excl_by_group(e_):
        e_._update_exclusion()
        return [bool(e_._excl[[x for x in e_.cluster_nodes[k].tolist() if x != e_._dns]].all())
                for k in range(e_.K)]
    eh = fresh(Nm); eh.state[eh._over[3][0]] = COMPROMISED
    check("a captured hypervisor excludes the defender from the on-premises servers and from nothing else",
          excl_by_group(eh) == [False, False, False, True, True, False] and int(eh._excl.sum()) == 14)
    em_ = fresh(Nm); em_.state[em_._over[0][0]] = COMPROMISED
    check("captured device management excludes the defender from the endpoints, remote ones included",
          excl_by_group(em_) == [True, True, True, False, False, False])
    ea = fresh(dataclasses.replace(Nm, ad_reach=0.0)); ea.state[ea.masters_of[1][1]] = COMPROMISED
    ea._update_exclusion()
    check("a Control Plane that reaches no node excludes the defender from none", int(ea._excl.sum()) == 0)
    src_nb = [layout["types"][int(e.cluster_of[x])] for x in e.adj[CONNECTION].get(e.source, ())]
    check("phishing lands on endpoints and exploits on servers",
          {"ep", "rem"} & set(src_nb) and {"sv", "cloud"} & set(src_nb), str(sorted(src_nb)))
    check("no master controller is reachable over a Connection",
          all(not e.adj[CONNECTION].get(int(m_)) for m_ in e.masters))
    j = int(e.cluster_nodes[1][2])
    e.state[e.masters_of[1][0]] = COMPROMISED
    check("with endpoint detection held the automated defence of the zone is off, the team still has access",
          e._system_held(1) and not e._auto_available(j) and not e._ad_held(1))
    e = fresh(Nm)
    e.state[e.masters_of[1][1]] = COMPROMISED
    e.state[j] = COMPROMISED; e.comp_ref[j] = 0
    def work(e_, t0, n_):
        for t_ in range(t0, t0 + n_):
            e_._tick = t_; e_._queue_step(t_)
    e._update_exclusion(); work(e, 400, 20)
    check("with Active Directory held the defender is excluded from the nodes it reaches, and only those",
          excl_by_group(e)[1] and not e.isolated[j] and not excl_by_group(e)[0] and not e._control_alive(j))
    e = fresh(Nm)
    e.state[e._dns] = COMPROMISED; e.comp_ref[e._dns] = 0
    e._update_exclusion()
    check("DNS is a Channel: held, it stops the automated defence everywhere but excludes nobody",
          e._dns_held() and int(e._excl.sum()) == 0 and not e._auto_available(j)
          and e._dns not in e.masters)
    before_ = int((e.state == COMPROMISED)[e.all_mask].sum()) + int((e._inf_ref >= 0).sum())
    e._tick = 3; e._channel_push(3)
    after_ = int((e.state == COMPROMISED)[e.all_mask].sum()) + int((e._inf_ref >= 0).sum())
    check("whoever holds DNS can deliver over the delivery channels that do not verify their supplier",
          after_ > before_ + 10, f"{after_ - before_} nodes reached")
    ev = fresh(dataclasses.replace(Nm, chan_verify=1.0))
    ev.state[ev._dns] = COMPROMISED; ev.comp_ref[ev._dns] = 0
    ev._tick = 3; ev._channel_push(3)
    check("and over none that do", int((ev._inf_ref >= 0).sum()) == 0)
    work(e, 400, 3)
    check("the team can restore DNS: after the investigation it is taken out of the attacker's hands",
          bool(e.isolated[e._dns]) and not e._dns_held())
    e = fresh(Nm)
    ad1 = e.masters_of[1][1]
    holder = e._cred[ad1][0]
    e.state[holder] = COMPROMISED; e.comp_ref[holder] = 0; e._comp_tick[holder] = 0
    e._L[holder] = 60.0
    e._controller_step(4)
    not_yet = e.state[ad1] != COMPROMISED
    e._L[holder] = 100.0
    e._controller_step(Nm.node_reconf - 1)
    too_soon = e.state[ad1] != COMPROMISED
    e._controller_step(5)
    check("Credential Access needs the Authority for it on the held node, and time to act",
          not_yet and too_soon and e.state[ad1] == COMPROMISED)
    em = fresh(dataclasses.replace(Nm, kind="malware"))
    hm = em._cred[em.masters_of[1][1]][0]
    em.state[hm] = COMPROMISED; em._rec[hm] = True; em._L[hm] = 100.0; em._comp_tick[hm] = 0
    em._controller_step(5)
    check("malware cannot use a credential", em.state[em.masters_of[1][1]] != COMPROMISED)
    e._controller_step(5 + Nm.repl_delay - 1)
    ads = [ms[1] for ms in e.masters_of if len(ms) > 1]
    early = sum(e.state[m_] == COMPROMISED for m_ in ads)
    e._controller_step(5 + Nm.repl_delay)
    late = sum(e.state[m_] == COMPROMISED for m_ in ads)
    check("a captured controller reaches the linked controllers after the replication delay",
          early == 1 and late == len(ads), f"{early} then {late}")
    Nf = dataclasses.replace(Nm, g=1.0, def_cap=1.0, horizon=300)
    e = fresh(Nf, 8, 64, 6101000); e.run()
    o = e.outcome()
    check("the run stops when the flag is captured",
          o["fl"] == 1 and len(e.rec.tick) == o["tf"] < 300 and o["f"] >= Nf.flag, f"flag at tick {o['tf']}")
    # ---- the payload: infected is not captured ----------------------------------
    Np = dataclasses.replace(Nm, payload_delay=5, dormant_share=0.0, g=0.0, n_chan=0, def_cap=100.0,
                             cap_spread=0.0)
    e = fresh(Np, 8, 8, 6101000)
    for _ in range(40):
        e._tick += 1; t_ = e._tick
        e._deliver(t_); e._advance_residents(t_); e._trigger(t_); e._record(t_)
    check("an infected node is not compromised, and a control stronger than the payload repels most of them",
          e.n_infected > 0 and e.n_repelled > 0
          and int(e._compromised_mask()[e.all_mask].sum()) <= e.n_infected - e.n_repelled)
    check("a repelled payload is seen by the defender, who blocks it", len(e._known_refs) > 0)
    Nq = dataclasses.replace(Np, coverage=0.0)
    e = fresh(Nq, 8, 8, 6101000)
    for _ in range(40):
        e._tick += 1; t_ = e._tick
        e._deliver(t_); e._advance_residents(t_); e._trigger(t_); e._record(t_)
    check("a node without the control cannot repel a payload",
          e.n_repelled == 0 and int(e._compromised_mask()[e.all_mask].sum()) > 0)
    # ---- delivery channels and staged rollout -------------------------------------
    def chan_reach(stage):
        kn = dataclasses.replace(Nm, stage_time=stage, coverage=0.0, g=0.0, payload=0, ext_share=0.0)
        e_ = fresh(kn, 9999, 9999, 6101000)
        s_ = e_._channels[0]["server"]
        e_.state[s_] = COMPROMISED; e_.comp_ref[s_] = 0
        for t_ in range(1, 6):
            e_._tick = t_; e_._channel_push(t_)
        return int(e_._compromised_mask()[e_.all_mask].sum())
    at_once, staged = chan_reach(0), chan_reach(64)
    check("a captured delivery channel reaches its nodes at once, and far fewer under a staged rollout",
          at_once > 20 and staged < at_once / 3, f"{at_once} against {staged} after 5 ticks")
    n4 = sum(len(v) for m_, v in fresh(Nm)._cred.items())
    n10 = sum(len(v) for m_, v in fresh(dataclasses.replace(Nm, seg_ep=8, seg_sv=4))._cred.items())
    check("the number of credential holders does not change with the segmentation", n4 == n10, f"{n4} and {n10}")
    ei = fresh(dataclasses.replace(Nm, kind="intrusion"))
    ei._seen_ref(123, 5)
    check("a hands-on intrusion leaves no signature to block", not ei.pending_blocks and not ei._sig)
    ef = fresh(dataclasses.replace(Nm, kind="implant", fixed_clock=1.0, dormant_delay=40))
    ef.first_seen_ref[777] = 10
    ef._arrive_at(int(ef.cluster_nodes[1][0]), 777, 2, 12); ef._arrive_at(int(ef.cluster_nodes[1][1]), 777, 2, 30)
    er = fresh(dataclasses.replace(Nm, kind="implant", fixed_clock=0.0, dormant_delay=40))
    er._arrive_at(int(er.cluster_nodes[1][0]), 777, 2, 12); er._arrive_at(int(er.cluster_nodes[1][1]), 777, 2, 30)
    check("a fixed clock triggers every payload of an attack on one tick; a relative one staggers them",
          set(ef._inf_due[ef._inf_ref >= 0].tolist()) == {50}
          and sorted(er._inf_due[er._inf_ref >= 0].tolist()) == [52, 70])
    e = fresh(Nm)
    kinds_x = sorted(ch["kind"] for ch in e._channels if ch["external"])
    check("the external parties are outside the estate and, by default, none holds a Control Plane",
          kinds_x == ["chan"] * 4 and int(e.hostile.sum()) == 6)
    reach_n = []
    for nx in (1, 4, 16):
        ex_ = fresh(dataclasses.replace(Nm, n_ext=nx))
        got = [j_ for ch in ex_._channels if ch["external"] for j_, _f in ch["served"]]
        reach_n.append((len(got), len(set(got))))
    check("the external parties' total reach is the same, and never overlaps, whatever their number",
          reach_n == [(40, 40)] * 3, str(reach_n))
    er_ = fresh(Nm)
    er_.state[er_.masters_of[1][0]] = COMPROMISED
    for t_ in range(1, 40):
        er_._controller_step(t_)
    check("replication does not carry an endpoint detection console's capture to the other consoles",
          sum(er_.state[ms[0]] == COMPROMISED for ms in er_.masters_of) == 1)
    # ---- the ceiling on a Channel and the alarm -----------------------------------
    def chan_arrival(ceil, cap, coverage=1.0, visibility=1.0):
        kn = dataclasses.replace(Nm, ceil_deliv=ceil, atk_cap=cap, cap_spread=0.0, dormant_share=0.0,
                                 coverage=coverage, visibility=visibility, payload_delay=50)
        e_ = fresh(kn)
        s_ = e_._channels[0]["server"]
        e_.state[s_] = COMPROMISED; e_.comp_ref[s_] = 0
        e_._tick = 1; e_._channel_push(1)
        return e_
    def trig(e_):
        e_._tick = 60; e_._trigger(60); e_._record(60)
        return (e_.state == COMPROMISED) & e_.all_mask & (e_._cause == 2)
    ec = chan_arrival(40.0, 90.0)
    hit = ec._inf_ref >= 0
    check("a payload delivered by a Channel runs on every node served, and its arrival raises no alarm",
          int(hit.sum()) > 20 and ec.n_alarms == 0 and float(ec._inf_capv[hit].max()) == 40.0)
    ec = chan_arrival(80.0, 30.0); got = trig(ec)
    check("held within the Channel's ceiling, the payload does what it wants silently: no escalation, no alarm",
          int(got.sum()) > 3 and ec.n_esc == 0 and ec.n_alarms == 0 and set(ec._L[got].tolist()) == {80.0})
    ec = chan_arrival(60.0, 30.0); got = trig(ec)
    lv = set(ec._L[got].tolist())
    check("above the ceiling it must escalate: every attempt is contested and alarms; a win gives the node's Authority",
          ec.n_esc == int(got.sum()) > 3 and ec.n_alarms == ec.n_esc and lv <= {60.0, 100.0}
          and int((ec._L[got] == 100.0).sum()) == ec.n_esc_won and int((ec._alarm >= 0).sum()) == ec.n_esc,
          f"{ec.n_esc_won} of {ec.n_esc} won")
    ec._reconfigure(60 + 100)
    check("a payload that came down a Channel reconfigures the node only after a won escalation",
          bool((ec._rec[got] == (ec._L[got] == 100.0)).all()))
    n_held = int(got.sum())
    work(ec, 61, 12)
    check("the team investigates the alarms and cleans the nodes",
          ec.q_started > 0 and int(((ec.state == COMPROMISED) & got).sum()) < n_held)
    ec = chan_arrival(60.0, 30.0, coverage=0.0); got = trig(ec)
    check("with no control on the node the escalation is uncontested and silent",
          ec.n_esc == ec.n_esc_won == int(got.sum()) > 20 and ec.n_alarms == 0)
    ec = chan_arrival(60.0, 30.0, visibility=0.0); got = trig(ec)
    check("an alarm on a node the defender cannot see reaches nobody",
          ec.n_alarms > 3 and int((ec._alarm >= 0).sum()) == 0)
    kn_ = dataclasses.replace(Nm, route_esc=0, cap_spread=0.0, dormant_share=0.0, payload_delay=50)
    ec = fresh(kn_); s_ = ec._channels[0]["server"]
    ec.state[s_] = COMPROMISED; ec.comp_ref[s_] = 0; ec._tick = 1; ec._channel_push(1); got = trig(ec)
    check("with Privilege Escalation switched off no attempt is made", int(got.sum()) > 3 and ec.n_esc == 0)
    ec = chan_arrival(1.0, 99.0, coverage=1.0)
    D_, A_ = 80.0, 99.0
    ec._tick = 60; ec._trigger(60)
    cap_n = int(((ec.state == COMPROMISED) & ec.all_mask).sum()) - 1
    tot_n = cap_n + ec.n_repelled
    check("the ceiling does not weaken the payload in the trigger contest",
          abs(cap_n / max(tot_n, 1) - A_ / (A_ + D_)) < 0.2, f"{cap_n} of {tot_n} captured")
    # ---- adaptation acts on evidence, and is work for the team -----------------------
    eq = fresh(dataclasses.replace(Nm, dose=1.0))
    sq = eq._channels[0]["server"]
    eq.state[sq] = COMPROMISED; eq.comp_ref[sq] = 0
    eq._tick = 1; eq._channel_push(1)
    before_q = len(eq._channels[0]["served"])
    eq._adapt_dom(0, 20)
    blind_q = len(eq._jobs)
    eq._evid.add(int(eq._channels[0]["served"][0][0]))
    eq._adapt_dom(0, 40)
    queued = len(eq._jobs)
    still = len(eq._channels[0]["served"])
    work(eq, 41, 6)
    check("the defender cuts a delivery relation only on evidence, and each cut is a job for the team",
          blind_q == 0 and queued > 0 and still == before_q and len(eq._channels[0]["served"]) < before_q,
          f"{before_q} served, {len(eq._channels[0]['served'])} after the cuts")
    # ---- Command and Control ------------------------------------------------------------
    e2 = fresh(dataclasses.replace(Nm, c2_share=0.5, kind="intrusion"))
    seg = [x for x in e2.cluster_nodes[1].tolist()]
    a_ = next(x for x in seg if e2._egress[x]); b_ = next(x for x in seg if not e2._egress[x])
    e2.state[b_] = COMPROMISED; e2._contact_update(); alone = bool(e2._contact[b_])
    e2.state[a_] = COMPROMISED; e2._contact_update()
    check("a held node with no route out is in the operator's reach only through a held neighbour that has one",
          not alone and bool(e2._contact[b_]) and bool(e2._contact[a_]))
    # ---- objective and value --------------------------------------------------------------
    # ---- the three stages of a held node (v0.17) ---------------------------------------
    def stage_test(kind, exfil_p, exfil_esc, win):
        e_ = fresh(dataclasses.replace(Nm, kind=kind, exfil_p=exfil_p, exfil_esc=exfil_esc, coverage=1.0,
                                       def_cap=(1.0 if win else 100.0), atk_cap=(100.0 if win else 1.0), cap_spread=0.0))
        sv = int(e_.cluster_nodes[3][0])
        # stage 1: a foothold, reclaimable, one exfiltration attempt
        e_.state[sv] = COMPROMISED; e_.comp_ref[sv] = 0; e_._L[sv] = 0.0; e_._comp_tick[sv] = 0
        e_._tick = 10; e_._impact_step(10); e_._reconfigure(10)
        s1 = (bool(e_._exfil[sv]), bool(e_._down[sv]), bool(e_._rec[sv]), e_._auto_available(sv) or not e_._sig)
        e_._impact_step(11)
        s1b = bool(e_._exfil[sv])
        # stage 2: escalation
        e_._escalate(sv, 0, 12)
        s2 = (bool(e_._exfil[sv]), bool(e_._down[sv]), bool(e_._rec[sv]), e_._auto_available(sv), bool(e_._rec3[sv]))
        # stage 3: held at stage 2 for node_reconf ticks
        e_._reconfigure(12); e_._impact_step(12)
        for t_ in range(13, 13 + Nm.node_reconf + 1):
            e_._reconfigure(t_); e_._impact_step(t_)
        s3 = (bool(e_._rec3[sv]), e_._control_alive(sv))
        return s1, s1b, s2, s3
    s1, s1b, s2, s3 = stage_test("intrusion", 0.0, 1.0, True)
    check("stage 1: a foothold is reclaimable, keeps the node running, and its one exfiltration attempt is not retried",
          s1 == (False, False, False, True) and s1b is False)
    check("stage 2: a won escalation makes the node unreclaimable in place and out of service, and gives data a "
          "second chance to leave", s2 == (True, True, True, False, False))
    check("stage 3: held at stage 2 for the reconfigure time, the node's agent is disabled",
          s3 == (True, False))
    _, _, s2m, _ = stage_test("malware", 1.0, 1.0, True)
    check("a payload that does not steal takes the node out at stage 2 but leaks nothing", s2m[:2] == (False, True))
    s1w, _, s2w, _ = stage_test("intrusion", 1.0, 0.0, False)
    check("exfiltration at stage 1 succeeds against a weak data control; a lost escalation leaves the node at stage 1",
          s1w[0] is True and s2w[1] is False and s2w[2] is False)
    def server_value(v):
        e_ = fresh(dataclasses.replace(Nm, val_sv=v))
        sv = np.zeros(e_.n, dtype=bool)
        for k in (3, 4, 5):
            sv[e_.cluster_nodes[k]] = True
        return float(e_._nval[sv & e_._ord].sum()) / e_._nval_tot
    check("node value sits with the servers: 71 per cent of it at a server value of 10, over 80 at 20",
          abs(server_value(10.0) - 200.0 / 280.0) < 1e-9 and server_value(20.0) > 0.8)
    ev_ = fresh(dataclasses.replace(Nm, kind="malware", val_sv=40.0, coverage=0.0, ext_share=0.0,
                                    ext_exploit=1.0, ep_sv=0.0, vpn=0.0, horizon=200), 8, 64, 6101000)
    ev_.run(); ov = ev_.outcome()
    check("the value flag falls when 80 per cent of node value is out of service, before 80 per cent of nodes are held",
          ov["wf"] == 2 and ov["fv"] == 1 and ov["f"] < 0.8, f"tick {ov['tf']}, {ov['f']:.0%} of nodes held")
    exc_ = layout.get("exceptional", [])
    check("a few endpoints carry exceptional data value, drawn from those holding a Control Plane credential",
          len(exc_) == 2 and all(any(x in v for m_, v in layout["cred"].items()
                                     if m_ in ("hv", "hvc", "mdm") or m_.endswith("m1")) for x in exc_), str(exc_))
    # ---- the team's queue ------------------------------------------------------------------
    def load(tb, n_bad=40, ticks=30):
        e_ = fresh(dataclasses.replace(Nm, tac_budget=tb, coverage=1.0, visibility=1.0, manual_scope=0))
        bad = [x for c_ in e_.cluster_nodes for x in c_.tolist() if x != e_._dns][:n_bad]
        for x in bad:
            e_.state[x] = COMPROMISED; e_.comp_ref[x] = 0
        peak_busy = 0
        for t_ in range(1, ticks + 1):
            e_._tick = t_; e_._queue_step(t_)
            peak_busy = max(peak_busy, sum(1 for jb in e_._jobs if jb["left"] >= 0))
        return e_, peak_busy, int((e_.state[bad] == COMPROMISED).sum())
    es_, busy_s, left_s = load(1.0)
    eb_, busy_b, left_b = load(10.0)
    check("the team never does more at once than it has responders, and a small team falls behind",
          busy_s <= es_.domains[0].tac_budget and busy_b <= eb_.domains[0].tac_budget
          and es_.q_wait / max(es_.q_started, 1) > 3 * eb_.q_wait / max(eb_.q_started, 1) and left_s > left_b,
          f"{es_.domains[0].tac_budget} responders leave {left_s} of 40, {eb_.domains[0].tac_budget} leave {left_b}")
    e1 = fresh(dataclasses.replace(Nm, tac_budget=0.3))
    ep_, sv_ = int(e1.cluster_nodes[0][1]), int(e1.cluster_nodes[3][1])
    for x in (ep_, sv_):
        e1.state[x] = COMPROMISED; e1.comp_ref[x] = 0
    e1._tick = 1; e1._queue_step(1)
    first = [jb["node"] for jb in e1._jobs if jb["left"] >= 0]
    check("work is taken in order of node value: the server before the endpoint", first == [sv_], str(first))
    e3 = fresh(Nm)
    con, ad_ = e3.masters_of[1][0], e3.masters_of[1][1]
    e3.state[con] = COMPROMISED; e3.comp_ref[con] = 0; e3.state[ad_] = COMPROMISED; e3.comp_ref[ad_] = 0
    seen_iso = False
    for t_ in range(1, 12):
        e3._tick = t_; e3._queue_step(t_); seen_iso = seen_iso or bool(e3.isolated[con])
    check("the team restores a captured endpoint detection console, a Channel service; "
          "a captured Control Plane is not rebuilt",
          seen_iso and e3.state[ad_] == COMPROMISED and not e3.isolated[ad_])
    # ---- sensitivity switches and the common observation times (v0.15) -------------------
    def conn_capture(ac):
        e_ = fresh(dataclasses.replace(Nm, kind="malware", auth_conn=ac, coverage=0.0, dormant_share=0.0))
        j_ = int(e_.cluster_nodes[1][4])
        e_._arrive_at(j_, 5, 1, 1); e_._tick = 9; e_._trigger(9)
        return e_.state[j_] == COMPROMISED, e_.n_esc, float(e_._L[j_])
    check("sensitivity: with a foothold of 0 a payload that came over a Connection must escalate; by the rule it holds 100",
          conn_capture(100.0) == (True, 0, 100.0) and conn_capture(0.0) == (True, 1, 100.0))
    def inert(flag_):
        e_ = fresh(dataclasses.replace(Nm, kind="intrusion", down_inert=flag_))
        ad_x = e_.masters_of[1][1]; h_ = e_._cred[ad_x][0]
        e_.state[h_] = COMPROMISED; e_.comp_ref[h_] = 0; e_._comp_tick[h_] = 0; e_._L[h_] = 100.0; e_._down[h_] = True
        e_._controller_step(6)
        return e_.state[ad_x] == COMPROMISED
    check("sensitivity: a node taken out can be used to take a credential by the rule, and not when it is inert",
          inert(0) and not inert(1))
    def cp_rebuild(mr):
        e_ = fresh(dataclasses.replace(Nm, master_rebuild=mr))
        ad_x = e_.masters_of[1][1]
        e_.state[ad_x] = COMPROMISED; e_.comp_ref[ad_x] = 0
        for t_ in range(1, 60):
            e_._tick = t_; e_._queue_step(t_)
        return e_.state[ad_x] != COMPROMISED
    check("sensitivity: a captured Control Plane is never rebuilt by the rule, and is when a rebuild time is set",
          not cp_rebuild(9999) and cp_rebuild(5))
    em_ = fresh(dataclasses.replace(Nm, horizon=30)); em_.run(); om = em_.outcome()
    check("damage is recorded at the common observation times, and marked absent once a run has stopped",
          om["d24"] >= 0 and om["s24"] >= 0 and om["d72"] == -1.0 and om["d168"] == -1.0)
    # ---- v0.18: the attacker's footholds, the hunt, visibility, known signatures -----------------
    er_ = fresh(dataclasses.replace(Nm, kind="intrusion", coverage=0.0, dormant_share=0.0, retool=10))
    fj = int(er_.cluster_nodes[1][5])
    er_.state[fj] = COMPROMISED; er_.comp_ref[fj] = er_._source_reference(1); er_._L[fj] = 0.0; er_._comp_tick[fj] = 0
    er_._tick = 1; er_._retool_retry(1); e1 = er_.n_esc
    er_._tick = 5; er_._retool_retry(5); e5 = er_.n_esc
    er_._tick = 12; er_._retool_retry(12); e12 = er_.n_esc
    check("a new payload from the source retries escalation on the attacker's footholds, once per re-tooling, "
          "and a foothold with no agent is taken silently on the first retry",
          e1 == 1 and e5 == 1 and e12 == 1 and er_._L[fj] == 100.0 and er_.n_alarms == 0)
    eo_ = fresh(dataclasses.replace(Nm, kind="intrusion", retry=0, coverage=0.0, dormant_share=0.0))
    eo_.state[fj] = COMPROMISED; eo_.comp_ref[fj] = 0; eo_._L[fj] = 0.0; eo_._comp_tick[fj] = 0
    eo_._tick = 30; eo_._retool_retry(30)
    check("with the retry switched off a foothold stays a foothold", eo_.n_esc == 0 and eo_._L[fj] == 0.0)
    eh_ = fresh(dataclasses.replace(Nm, kind="implant", visibility=0.5, tac_budget=10.0, manual_delay=1))
    seg = [x for x in eh_.cluster_nodes[1].tolist() if x != eh_._dns]
    vis_j = next(x for x in seg if eh_.net.visible[x]); inv_j = next(x for x in seg if not eh_.net.visible[x])
    noag = fresh(dataclasses.replace(Nm, kind="implant", coverage=0.0))
    for x in (vis_j, inv_j):
        eh_.state[x] = COMPROMISED; eh_.comp_ref[x] = 55; eh_._comp_tick[x] = 0
    eh_._alarm[vis_j] = 1
    for t_ in range(1, 4):
        eh_._tick = t_; eh_._queue_step(t_)
    check("hunt on alarm: the investigation of an alarmed node finds the same payload on every agent, visible or not",
          bool(eh_._known[inv_j]) and eh_.n_hunt >= 1)
    check("and a known signature is pushed to every agent", any(55 in eh_.blacklist[x] for x in seg) or eh_.pending_blocks)
    ev_ = fresh(dataclasses.replace(Nm, kind="malware", visibility=0.5, def_cap=100.0, atk_cap=1.0, cap_spread=0.0, payload_delay=1))
    inv2 = next(x for x in ev_.cluster_nodes[0].tolist() if x != ev_._dns and not ev_.net.visible[x] and ev_._has_control[x])
    ev_._arrive_at(inv2, 77, 1, 1); ev_._tick = 2; ev_._trigger(2)
    check("a repel on an invisible node stays local: no signature is published", ev_.n_repelled == 1 and 77 not in ev_._known_refs)
    ek_ = fresh(dataclasses.replace(Nm, kind="malware", def_cap=1.0, atk_cap=100.0, cap_spread=0.0, sig_block=0.99))
    kj = int(ek_.cluster_nodes[0][1]); ek_.blacklist[kj].add(88)
    hits = sum(ek_._repels(kj, 88) for _ in range(2000))
    ek0 = fresh(dataclasses.replace(Nm, kind="malware", def_cap=1.0, atk_cap=100.0, cap_spread=0.0, sig_block=-1.0))
    ek0.blacklist[kj].add(88)
    check("a known signature is matched with 99 per cent reliability, and the capability contest follows a miss",
          1900 < hits < 2000 and all(ek0._repels(kj, 88) for _ in range(50)), f"{hits} of 2000")
    # ---- exposure by count ------------------------------------------------------------------
    def n_cred(**kw):
        _sp, lay, _b = generate(dataclasses.replace(Nm, **kw), 0)
        return {k_: len(v) for k_, v in lay["cred"].items()}
    c0, c1, c7 = n_cred(cred_total=0), n_cred(cred_total=1), n_cred(cred_total=7)
    cm = n_cred(cred_total=1, cred_only="mdm")
    cad = n_cred(cred_total=3, cred_only="ad")
    check("exposure by count places exactly that many credentials, with no rounding up",
          sum(c0.values()) == 0 and sum(c1.values()) == 1 and sum(c7.values()) == 7)
    check("and only for the services allowed",
          cm == {**{k_: 0 for k_ in cm}, "mdm": 1} and sum(cad.values()) == 3
          and all(v == 0 for k_, v in cad.items() if not k_.endswith("m1")))
    check("a share of 1 per cent rounds up to one holder per service, which is what the drill avoids",
          sum(n_cred(g=0.01).values()) >= 6)
    # ---- External Trust and the estate that is counted --------------------------------------
    ex_ = fresh(dataclasses.replace(Nm, ext_auth=1.0, ext_bad=1.0, kind="intrusion"))
    for t_ in range(1, Nm.reconf_time + 3):
        ex_._tick = t_; ex_._channel_push(t_)
    ex_._update_exclusion()
    reach_x = [j_ for ch in ex_._channels if ch["external"] for j_, _f in ch["served"]]
    check("a compromised third party holding Authority reconfigures the nodes it directs and excludes the defender",
          len(reach_x) == 40 and bool((ex_.state[reach_x] == COMPROMISED).all())
          and bool(ex_._rec[reach_x].all()) and bool(ex_._excl[reach_x].all()) and int(ex_._excl.sum()) == 40)
    check("the estate that is counted is its 100 endpoints and servers, wherever its services are run",
          len(fresh(Nm)._def_idx) == 100 and len(fresh(dataclasses.replace(Nm, edr_site=1, dns_site=1))._def_idx) == 100)
    el_ = fresh(dataclasses.replace(Nm, kind="malware", route_lat=0))
    ec_ = fresh(dataclasses.replace(Nm, kind="intrusion", route_cred=0))
    check("the stage switches turn off Lateral Movement and Credential Access",
          not el_._k_spread and not ec_._k_cred)
    Nb = dataclasses.replace(Nm, ext_bad=0.5)
    bad_n = [int(sum(fresh(Nb, seed=6101000 + i_).state[x] == COMPROMISED for x in e._ext)) for i_ in range(40)]
    check("each external party is compromised with the set chance, drawn afresh each run",
          0 in bad_n or 4 in bad_n or len(set(bad_n)) > 2, f"mean {np.mean(bad_n):.1f} of 4")
    en_ = fresh(dataclasses.replace(Nm, coverage=0.0))
    jn = int(en_.cluster_nodes[1][0])
    en_.state[jn] = COMPROMISED; en_.comp_ref[jn] = 0; en_._tick = 50
    ey_ = fresh(Nm)
    ey_.state[jn] = COMPROMISED; ey_.comp_ref[jn] = 0; ey_._tick = 50
    check("a compromise is reported only by a node with a control whose alarms the defender can see",
          not en_._picture(en_.domains[0])[jn] and bool(ey_._picture(ey_.domains[0])[jn]))
    # ---- services sited with a third party ------------------------------------------
    Ns = dataclasses.replace(Nm, kind="implant", edr_site=1, dns_site=1, ext_bad=1.0)
    es = fresh(Ns)
    check("sited outside and compromised, endpoint detection and DNS are the attacker's from the start",
          es._dns_held() and all(es._system_held(k) for k in range(es.K))
          and es._dns not in set(np.flatnonzero(es.all_mask).tolist()))
    es2 = fresh(dataclasses.replace(Ns, ext_bad=0.0))
    check("sited outside with a sound third party, they are not",
          not es2._dns_held() and not any(es2._system_held(k) for k in range(es2.K)))
    es3 = fresh(dataclasses.replace(Ns, kind="malware"))
    check("a third party's compromise matters only to an attack that works through a supplier",
          not es3._dns_held() and not any(es3._system_held(k) for k in range(es3.K)))
    # ---- reconfigure ----------------------------------------------------------------
    e = fresh(Nm)
    j = int(e.cluster_nodes[1][3])
    e.state[j] = COMPROMISED; e.comp_ref[j] = 0; e._L[j] = 100.0
    e._record(1); e._reconfigure(1)
    soon = bool(e._rec[j])
    e._record(1 + Nm.node_reconf); e._reconfigure(1 + Nm.node_reconf)
    check("a node held long enough is reconfigured, and then only a manual rebuild recovers it",
          not soon and bool(e._rec[j]) and not e._auto_available(j))
    # analysis
    a = dict(C=np.array([0.0, 1.0]), S=np.array([0.0, 1.0]), R=np.array([1.0, 1.0]), A=np.array([0.1, 0.9]))
    b = dict(C=np.array([0.0, 0.0]), S=np.array([0.0, 0.5]), R=np.array([1.0, 1.0]), A=np.array([0.1, 0.5]))
    e_ = _effect(a, b)
    check("effect is the mean change over the grid",
          abs(e_["C"][0] - 0.5) < 1e-12 and e_["R"][0] == 0 and abs(e_["A"][1] - 0.2) < 1e-12)
    check("named dial levels order by their ladder (v0.19 fix: the screen's knob summary failed on queue_order and objective)",
          _lv("fifo", "queue_order") == 1.0 and _lv("destroy", "objective") == 1.0 and _lv("kind", "objective") == -1.0
          and _lv("majority", "theta") == 1.0 and _lv(0.5, "coverage") == 0.5)
    check("the model digest is recorded; it differs from the v0.18 freeze (v0.21 reopened the model for stolen credentials)",
          MODEL_DIGEST != "unavailable" and MODEL_DIGEST != MODEL_DIGEST_V018, MODEL_DIGEST[:16])
    # ---- v0.21: stolen service credentials, rotation, the campaign ------------------------------
    def landed(e_, j_, ref_, t_):
        e_._arrive_at(j_, ref_, 1, t_); e_._tick = t_ + 1; e_._trigger(t_ + 1)
    es_ = fresh(dataclasses.replace(Nm, kind="stealer", coverage=0.0, steal_p=1.0, dormant_share=0.0))
    m_ = next(m for m, v in es_._cred.items() if v)
    cj = int(es_._cred[m_][0])
    landed(es_, cj, 301, 1)
    es0 = fresh(dataclasses.replace(Nm, kind="stealer", coverage=0.0, steal_p=0.0, dormant_share=0.0))
    landed(es0, cj, 301, 1)
    es_._retool_retry(40)
    check("a stealer landing on a node that holds a service credential takes it with probability steal_p, "
          "needs no Authority, and cannot itself use it",
          es_.state[cj] == COMPROMISED and cj in es_._stolen.get(m_, {}) and es_.n_stolen >= 1
          and not es0._stolen and es_.state[m_] != COMPROMISED and es_.n_spent == 0)
    ec_ = fresh(dataclasses.replace(Nm, kind="campaign", coverage=0.0, steal_p=1.0, dormant_share=0.0, handoff=20, retool=10))
    landed(ec_, cj, 302, 1)
    ph0 = ec_._phase
    ec_._tick = 21
    if ec_._kind == "campaign" and ec_._phase == "stealer" and 21 > ec_.o.handoff:
        ec_._apply_kind("intrusion"); ec_._spend_credentials(21)
    check("a campaign runs as a stealer until the handoff, then as an intrusion that spends the stolen "
          "credential from any held node and takes the service",
          ph0 == "stealer" and ec_._phase == "intrusion" and not ec_._sig and ec_._k_cred
          and ec_.state[m_] == COMPROMISED and ec_.n_spent >= 1 and ec_._cause[m_] == 3)
    # rotation: the team cleans the node the credential was taken from
    def stolen_after_clean(rot):
        e_ = fresh(dataclasses.replace(Nm, kind="stealer", coverage=0.0, steal_p=1.0, dormant_share=0.0, rotate=rot,
                                       def_cap=100.0, atk_cap=1.0, cap_spread=0.0))   # the clean is certain to work
        landed(e_, cj, 303, 1)
        other = [x for x in e_._cred[m_] if x != cj]
        if other:
            e_._stolen[m_][int(other[0])] = 1      # the same service's credential also taken elsewhere
        e_._tick = 5
        e_._job_done(dict(kind="clean", key=cj, node=cj), 5)
        return dict(e_._stolen.get(m_, {})), bool(other)
    r0, _ = stolen_after_clean(0); r1, had = stolen_after_clean(1); r2, _ = stolen_after_clean(2)
    check("rotation: 0 keeps a stolen credential after the node is cleaned; 1 rotates the cleaned node's; "
          "2 rotates every stolen credential of that service",
          cj in r0 and cj not in r1 and (not had or len(r1) == 1) and not r2)
    et_ = fresh(dataclasses.replace(Nm, kind="campaign", coverage=0.0, steal_p=1.0, dormant_share=0.0, cred_ttl=10, handoff=0))
    et_._stolen[m_] = {cj: 1}
    et_._apply_kind("intrusion")
    et_._tick = 30; et_._spend_credentials(30)
    check("a stolen credential past its validity is dropped unused", not et_._stolen and et_.n_spent == 0)
    # the hands-on attacker keeps what Credential Access took
    ei_ = fresh(dataclasses.replace(Nm, kind="intrusion", coverage=0.0, dormant_share=0.0, rotate=0, retool=10))
    ei_.state[cj] = COMPROMISED; ei_.comp_ref[cj] = 10_000; ei_._L[cj] = 100.0; ei_._comp_tick[cj] = 0
    ei_._tick = 10; ei_._controller_step(10)
    took = ei_.state[m_] == COMPROMISED and cj in ei_._stolen.get(m_, {})
    ei_.state[m_] = 0                             # the defender recovers the service by hand
    ei_._reset_node(cj); ei_.state[cj] = 0        # and cleans the holder (rotate = 0: nothing rotated)
    oj = int(ei_.cluster_nodes[0][2]) if int(ei_.cluster_nodes[0][2]) != cj else int(ei_.cluster_nodes[0][3])
    ei_.state[oj] = COMPROMISED; ei_.comp_ref[oj] = 10_000; ei_._L[oj] = 0.0; ei_._comp_tick[oj] = 10
    ei_._tick = 20; ei_._retool_retry(20)
    check("Credential Access leaves the credential in the attacker's store: once the service is recovered and the "
          "holder cleaned without rotation, the next payload retakes it from any other foothold",
          took and ei_.state[m_] == COMPROMISED and ei_.n_spent == 1)
    print("SELF-TEST " + ("PASSED" if ok_all else "FAILED"))
    return ok_all


# ============================================================================
# Entry point
# ============================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description=CODE_VERSION)
    ap.add_argument("--mode", default="selftest",
                    choices=["selftest", "gate0", "time", "plan", "screen", "analyse", "sweep", "smoke", "curves", "ablate", "paired", "grid", "confirm", "drill"])
    ap.add_argument("--out-root", default=None)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--run-dir", default=None,
                    help="screen: resume this run directory; analyse: the directory to analyse")
    ap.add_argument("--ref", default=None, help="gate0: path to PhDPaper4B.py (v0.23)")
    ap.add_argument("--reps", type=int, default=None, help="gate0: runs per seed block")
    ap.add_argument("--quick", action="store_true", help="gate0: short horizon, 2 runs per block; confirm, drill: dry run")
    ap.add_argument("--final", action="store_true", help="confirm: the final confirmation on the fresh reserved draws (v0.3)")
    ap.add_argument("--steps", type=int, default=99,
                    help="at most this many levels per knob ladder (default: every level)")
    ap.add_argument("--knobs", default=None, help="comma-separated knob names (default: all)")
    ap.add_argument("--topology", default=None, help="restrict to chain, star or mesh")
    ap.add_argument("--gamma", type=int, default=None, choices=[0, 1], help="restrict scope")
    ap.add_argument("--cap-rule", default="ratio", choices=["ratio", "cutoff", "fixed"],
                    help="how relative capability sets the chance a defender action works "
                         "(default: ratio, the contest success function)")
    ap.add_argument("--point", default=None, choices=sorted(POINTS),
                    help="screen: the background every knob is stepped against (default neutral)")
    ap.add_argument("--backgrounds", default=None,
                    help="sweep, smoke: comma-separated backgrounds (default: all three for the "
                         "sweep, strong and middle for the smoke test)")
    ap.add_argument("--kinds", default=",".join(KINDS),
                    help="sweep, smoke: comma-separated attack kinds (default: all four)")
    a = ap.parse_args(argv)
    pf = os.path.join(a.run_dir, "point.txt") if a.run_dir else None
    if pf and os.path.exists(pf):
        saved = open(pf, encoding="utf-8").read().strip()
        if a.point and a.point != saved:
            ap.error(f"this run directory was started from the '{saved}' point")
        a.point = saved
    set_point(a.point or "neutral")
    workers = a.workers if a.workers else _default_workers()
    knobs = a.knobs.split(",") if a.knobs else None
    if knobs:
        unknown = [k for k in knobs if k not in REGISTER]
        if unknown:
            ap.error("unknown knob(s): " + ", ".join(unknown))
    tops = [a.topology] if a.topology else None
    gams = [a.gamma] if a.gamma is not None else None
    print(f"{CODE_VERSION}; frozen core {EMBEDDED_SET_DIGEST[:12]} verified: "
          f"{all(_FREEZE_REPORT.values())}; Python {sys.version.split()[0]}", flush=True)
    if a.mode == "selftest":
        sys.exit(0 if mode_selftest() else 1)
    if a.mode == "gate0":
        sys.exit(0 if mode_gate0(a.out_root, workers, a.ref, a.reps, a.quick) else 1)
    if a.mode == "time":
        mode_time(workers, a.steps)
    elif a.mode == "plan":
        mode_plan(a.steps, knobs, tops, gams)
    elif a.mode == "screen":
        mode_screen(a.out_root, workers, a.steps, knobs, tops, gams, a.run_dir, a.cap_rule)
    elif a.mode in ("sweep", "smoke"):
        bgs = [b for b in a.backgrounds.split(",") if b] if a.backgrounds else None
        bad_b = [b for b in (bgs or []) if b not in POINTS]
        if bad_b:
            ap.error("unknown background(s): " + ", ".join(bad_b))
        kds = [k for k in a.kinds.split(",") if k]
        bad_k = [k for k in kds if k not in KINDS + ("mixed",)]
        if bad_k:
            ap.error("unknown attack kind(s): " + ", ".join(bad_k))
        mode_sweep(a.out_root, workers, a.steps, knobs, tops, gams, a.run_dir, a.cap_rule, bgs,
                   smoke=(a.mode == "smoke"), kinds=kds)
    elif a.mode == "ablate":
        mode_ablate(a.out_root, workers, full=not a.quick and a.steps < 99,
                    kinds=[k for k in a.kinds.split(",") if k],
                    backgrounds=[b for b in a.backgrounds.split(",") if b] if a.backgrounds else None)
    elif a.mode == "drill":
        mode_drill(a.out_root, workers, run_dir=a.run_dir, dry=bool(a.quick))
    elif a.mode == "confirm":
        mode_confirm(a.out_root, workers, run_dir=a.run_dir, dry=bool(a.quick), final=bool(a.final))
    elif a.mode == "grid":
        mode_grid(a.out_root, workers,
                  kinds=[k for k in a.kinds.split(",") if k],
                  backgrounds=[b for b in a.backgrounds.split(",") if b] if a.backgrounds else None)
    elif a.mode == "paired":
        mode_paired(a.out_root, workers,
                    kinds=[k for k in a.kinds.split(",") if k] if a.kinds != ",".join(KINDS) else None,
                    backgrounds=[b for b in a.backgrounds.split(",") if b] if a.backgrounds else None,
                    knobs=knobs)
    elif a.mode == "curves":
        if not a.run_dir:
            ap.error("--mode curves needs --run-dir (a sweep directory)")
        mode_curves(a.run_dir)
    elif a.mode == "analyse":
        if not a.run_dir:
            ap.error("--mode analyse needs --run-dir")
        mode_analyse(a.run_dir)


if __name__ == "__main__":
    main()
