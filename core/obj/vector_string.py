from core.analyser.cvss.cvss_record_template_v3 import *


class VectorString:
    def __init__(self, av: AttackVector = None, ac: AttackComplexity = None, pr: PrivilegesRequired = None, ui: UserInteraction = None, s: Scope = None, c: ConfidentialityImpact = None, i: IntegrityImpact = None, a: AvailabilityImpact = None) -> None:
        self.av = av
        self.ac = ac
        self.pr = pr
        self.ui = ui
        self.s = s
        self.c = c
        self.i = i
        self.a = a

    def __str__(self) -> str:
        ret_str = ""
        ret_str += "AV:"+self.av[0]+"/" if self.av else ""
        ret_str += "AC:"+self.ac[0]+"/" if self.ac else ""
        ret_str += "PR:"+self.pr[0]+"/" if self.pr else ""
        ret_str += "UI:"+self.ui[0]+"/" if self.ui else ""
        ret_str += "S:"+self.s[0]+"/" if self.s else ""
        ret_str += "C:"+self.c[0]+"/" if self.c else ""
        ret_str += "I:"+self.i[0]+"/" if self.i else ""
        ret_str += "A:"+self.a[0]+"/" if self.a else ""
        return ret_str[:-1]
