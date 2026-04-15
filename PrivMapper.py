#!/usr/bin/env python3
"""
pmapper_iam.py — AWS IAM review and HTML report in one script
Usage: python3 pmapper_iam.py [profile1 profile2 ...]

Runs pmapper graph creation and all IAM queries across given profiles,
then generates a single HTML report.

If profiles are omitted, edit the PROFILES list below.
"""

import os, sys, re, subprocess, json, shutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# Configure profiles here if not passing as arguments
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_PROFILES = [
    "profile-account-a",
    "profile-account-b",
]

# Opt-in / unreachable regions to skip during graph creation
# EXCLUDE_REGIONS = "me-south-1 ap-east-1 af-south-1 eu-south-1 me-central-1 ap-southeast-3"

# ─────────────────────────────────────────────────────────────────────────────
# IAM check definitions
# ─────────────────────────────────────────────────────────────────────────────
IAM_CHECKS = {
    "iam_create_user","iam_create_access_key","iam_create_login_profile",
    "iam_attach_user_policy","iam_attach_role_policy","iam_attach_group_policy",
    "iam_put_user_policy","iam_put_role_policy","iam_set_default_policy_version",
    "iam_passrole","iam_update_assume_role_policy","sts_assumerole",
}
S3_CHECKS      = {"s3_get_object","s3_put_bucket_policy"}
CRED_CHECKS    = {"secretsmanager_get","ssm_get_parameter","ssm_get_parameters"}
EVASION_CHECKS = {"cloudtrail_stop","cloudtrail_delete","guardduty_delete"}
COMPUTE_CHECKS = {
    "ec2_run_instances","lambda_update_code","lambda_add_permission","lambda_create_function",
    "glue_create_job","glue_update_job","cloudformation_create_stack","cloudformation_update_stack",
    "codebuild_create_project","codebuild_start_build","sagemaker_create_training",
    "sagemaker_create_notebook","ecs_run_task","ecs_register_task_definition",
    "states_create_statemachine","datapipeline_create_pipeline",
}
IAM_WILDCARD_THRESHOLD = 6

# Human-readable label for each check
CHECK_LABEL = {
    "iam_create_user":               "Create new IAM users (persistent backdoor accounts)",
    "iam_create_access_key":         "Generate long-term access keys for any IAM user",
    "iam_create_login_profile":      "Set a console password for any IAM user",
    "iam_attach_user_policy":        "Attach AdministratorAccess to any IAM user",
    "iam_attach_role_policy":        "Attach AdministratorAccess to any IAM role",
    "iam_attach_group_policy":       "Attach AdministratorAccess to any IAM group",
    "iam_put_user_policy":           "Write allow-all inline policies to any IAM user",
    "iam_put_role_policy":           "Write allow-all inline policies to any IAM role",
    "iam_set_default_policy_version":"Revert managed policies to older permissive versions",
    "iam_passrole":                  "Pass privileged roles to EC2, Lambda, ECS, or other services",
    "iam_update_assume_role_policy": "Rewrite role trust policies to grant themselves access",
    "sts_assumerole":                "Assume other IAM roles and inherit their full permissions",
    "secretsmanager_get":            "Retrieve all Secrets Manager secrets in plaintext",
    "ssm_get_parameter":             "Read SSM Parameter Store values including encrypted secrets",
    "ssm_get_parameters":            "Bulk retrieve all SSM Parameter Store values at once",
    "s3_get_object":                 "Download any object from S3 buckets",
    "s3_put_bucket_policy":          "Rewrite S3 bucket policies to expose buckets publicly",
    "ec2_run_instances":             "Launch EC2 instances with privileged instance profiles",
    "lambda_update_code":            "Replace Lambda function code to abuse the execution role",
    "lambda_add_permission":         "Grant external accounts access to Lambda functions",
    "lambda_create_function":        "Create new Lambda functions with a privileged execution role",
    "glue_create_job":               "Create Glue ETL jobs running with a privileged role",
    "glue_update_job":               "Modify existing Glue jobs to run with a privileged role",
    "cloudformation_create_stack":   "Deploy CloudFormation stacks under a privileged role",
    "cloudformation_update_stack":   "Update CloudFormation stacks to change resource permissions",
    "codebuild_create_project":      "Create CodeBuild projects with a privileged role",
    "codebuild_start_build":         "Trigger CodeBuild builds that execute with a privileged role",
    "sagemaker_create_training":     "Create SageMaker training jobs with a privileged execution role",
    "sagemaker_create_notebook":     "Create SageMaker notebook instances with a privileged role",
    "ecs_run_task":                  "Run ECS tasks with a privileged task role",
    "ecs_register_task_definition":  "Register ECS task definitions that assign privileged task roles",
    "states_create_statemachine":    "Create Step Functions state machines with a privileged role",
    "datapipeline_create_pipeline":  "Create Data Pipelines running with a privileged role",
    "cloudtrail_stop":               "Stop CloudTrail logging (removes audit trail)",
    "cloudtrail_delete":             "Delete CloudTrail trails permanently",
    "guardduty_delete":              "Delete GuardDuty detectors (disables threat detection)",
    "rds_describe":                  "Enumerate all RDS database instances and endpoints",
    "organizations_create_policy":   "Create Service Control Policies affecting all org accounts",
}

# Queries: (output_key, pmapper_query_string)
QUERIES = [
    ("iam_create_user",              "who can do iam:CreateUser"),
    ("iam_create_access_key",        "who can do iam:CreateAccessKey"),
    ("iam_create_login_profile",     "who can do iam:CreateLoginProfile"),
    ("iam_attach_user_policy",       "who can do iam:AttachUserPolicy"),
    ("iam_attach_role_policy",       "who can do iam:AttachRolePolicy"),
    ("iam_attach_group_policy",      "who can do iam:AttachGroupPolicy"),
    ("iam_put_user_policy",          "who can do iam:PutUserPolicy"),
    ("iam_put_role_policy",          "who can do iam:PutRolePolicy"),
    ("iam_set_default_policy_version","who can do iam:SetDefaultPolicyVersion"),
    ("iam_passrole",                 "who can do iam:PassRole"),
    ("sts_assumerole",               "who can do sts:AssumeRole"),
    ("iam_update_assume_role_policy","who can do iam:UpdateAssumeRolePolicy"),
    ("secretsmanager_get",           "who can do secretsmanager:GetSecretValue"),
    ("ssm_get_parameter",            "who can do ssm:GetParameter"),
    ("ssm_get_parameters",           "who can do ssm:GetParameters"),
    ("s3_get_object",                "who can do s3:GetObject"),
    ("s3_put_bucket_policy",         "who can do s3:PutBucketPolicy"),
    ("ec2_run_instances",            "who can do ec2:RunInstances"),
    ("lambda_update_code",           "who can do lambda:UpdateFunctionCode"),
    ("lambda_add_permission",        "who can do lambda:AddPermission"),
    ("lambda_create_function",       "who can do lambda:CreateFunction"),
    ("glue_create_job",              "who can do glue:CreateJob"),
    ("glue_update_job",              "who can do glue:UpdateJob"),
    ("cloudformation_create_stack",  "who can do cloudformation:CreateStack"),
    ("cloudformation_update_stack",  "who can do cloudformation:UpdateStack"),
    ("codebuild_create_project",     "who can do codebuild:CreateProject"),
    ("codebuild_start_build",        "who can do codebuild:StartBuild"),
    ("sagemaker_create_training",    "who can do sagemaker:CreateTrainingJob"),
    ("sagemaker_create_notebook",    "who can do sagemaker:CreateNotebookInstance"),
    ("ecs_run_task",                 "who can do ecs:RunTask"),
    ("ecs_register_task_definition", "who can do ecs:RegisterTaskDefinition"),
    ("states_create_statemachine",   "who can do states:CreateStateMachine"),
    ("datapipeline_create_pipeline", "who can do datapipeline:CreatePipeline"),
    ("cloudtrail_stop",              "who can do cloudtrail:StopLogging"),
    ("cloudtrail_delete",            "who can do cloudtrail:DeleteTrail"),
    ("guardduty_delete",             "who can do guardduty:DeleteDetector"),
    ("organizations_create_policy",  "who can do organizations:CreatePolicy"),
    ("rds_describe",                 "who can do rds:DescribeDBInstances"),
]

AWS_MANAGED_PATTERNS = [
    r"OrganizationAccountAccessRole", r"AWSReservedSSO_", r"AWSServiceRoleFor",
    r"aws-reserved", r"AWSControlTower", r"aws-controltower",
    r"stacksets-exec-", r"StackSet-", r"AWSBackup", r"AWSConfig", r"AWSServiceRole",
]

TECHNIQUES = [
    ("Direct STS AssumeRole",        [r"sts:AssumeRole", r"access via sts"]),
    ("Lambda Function Code Update",  [r"[Ll]ambda", r"edit.*function", r"function.*code"]),
    ("CodeBuild Project Abuse",      [r"[Cc]ode[Bb]uild"]),
    ("Access Key Creation",          [r"access key", r"[Cc]reate[Aa]ccess[Kk]ey"]),
    ("Policy Attachment",            [r"attach.*polic", r"put.*polic"]),
    ("EC2 Instance Profile",         [r"[Ee][Cc]2", r"instance profile", r"[Rr]un[Ii]nstances"]),
    ("CloudFormation Stack",         [r"[Cc]loud[Ff]ormation"]),
    ("Glue Job",                     [r"[Gg]lue"]),
    ("Role Trust Policy Modification",[r"trust.*doc", r"[Uu]pdate[Aa]ssume"]),
]

# ─────────────────────────────────────────────────────────────────────────────
# Terminal output helpers
# ─────────────────────────────────────────────────────────────────────────────
RED="\033[1;31m"; GRN="\033[1;32m"; YEL="\033[1;33m"; BLU="\033[1;34m"; NC="\033[0m"
def log(msg):  print(f"\n{BLU}[*]{NC} {msg}")
def ok(msg):   print(f"{GRN}[+]{NC} {msg}")
def warn(msg): print(f"{YEL}[!]{NC} {msg}")
def err(msg):  print(f"{RED}[-]{NC} {msg}")

# ─────────────────────────────────────────────────────────────────────────────
# Pmapper runner
# ─────────────────────────────────────────────────────────────────────────────
def pmrun(profile, args, outfile=None, label=""):
    """Run a pmapper command. Append output to outfile if given. Never raises."""
    env = os.environ.copy()
    env["AWS_STS_REGIONAL_ENDPOINTS"] = "legacy"
    cmd = ["pmapper", "--profile", profile] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        output = result.stdout + result.stderr
        if outfile:
            Path(outfile).parent.mkdir(parents=True, exist_ok=True)
            with open(outfile, "a") as f:
                f.write(output)
        if result.returncode == 0:
            if label: ok(f"  {label}")
            return True, output
        else:
            if label: warn(f"  {label} (non-zero exit — continuing)")
            return False, output
    except FileNotFoundError:
        err("pmapper not found — install with: pip install principalmapper")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        if label: warn(f"  {label} (timeout)")
        return False, ""
    except Exception as ex:
        if label: warn(f"  {label} ({ex})")
        return False, ""

def run_review(profiles, outdir):
    """Run pmapper graph creation and all queries for each profile."""
    Path(outdir).mkdir(parents=True, exist_ok=True)
    ok(f"Output directory: {outdir}")

    for profile in profiles:
        log(f"{'═'*50}")
        log(f"Profile: {profile}")
        log(f"{'═'*50}")

        pdir      = Path(outdir) / profile
        preset_dir = pdir / "presets"
        query_dir  = pdir / "queries"
        for d in (pdir, preset_dir, query_dir):
            d.mkdir(parents=True, exist_ok=True)

        # 1. Graph create
        log("[1/4] Graph creation")
        graph_log = pdir / "01_graph_create.log"
        success, output = pmrun(profile,
            ["graph", "create", "--exclude-regions"] + EXCLUDE_REGIONS.split(),
            str(graph_log), "graph create")

        # Verify graph exists even if exit code was non-zero
        stats_check, stats_out = pmrun(profile, ["graph", "display"])
        if "Nodes" in stats_out or "nodes" in stats_out:
            ok("  Graph verified")
        elif not success:
            err(f"  Graph creation failed — skipping {profile}")
            continue

        # 2. Graph stats
        log("[2/4] Graph stats")
        stats_file = pdir / "02_graph_stats.txt"
        pmrun(profile, ["graph", "display"], str(stats_file), "graph stats")

        # 3. Preset queries
        log("[3/4] Preset queries")
        presets = [
            ("privesc_all.txt",   ["query",    "preset privesc *"],     "privesc (all)"),
            ("privesc_skip.txt",  ["query","-s","preset privesc *"],    "privesc (non-admins)"),
            ("endgame_all.txt",   ["query",    "preset endgame *"],     "endgame"),
            ("serviceaccess.txt", ["query",    "preset serviceaccess"], "service access"),
            ("wrongadmin.txt",    ["query",    "preset wrongadmin *"],  "wrong admin"),
        ]
        for fname, args, label in presets:
            outf = preset_dir / fname
            outf.write_text(f"Query: {args[-1]}\n---\n")
            pmrun(profile, args, str(outf), label)

        # 4. Manual queries
        log("[4/4] Manual queries")
        total = len(QUERIES)
        for i, (key, query) in enumerate(QUERIES, 1):
            outf = query_dir / f"{key}.txt"
            outf.write_text(f"Query: {query}\n---\n")
            pmrun(profile, ["query", query], str(outf))
            # Progress bar
            pct  = int(i / total * 30)
            bar  = "█" * pct + "░" * (30 - pct)
            print(f"\r  [{bar}] {i}/{total} {key:<40}", end="", flush=True)
        print()

        # SVG graph visualisation
        # pmapper visualize writes to ~/.local/share/principalmapper/<account_id>/
        # We run it then search for the newest SVG in the pmapper data dir and copy it
        log("[5/5] SVG visualisation")
        svg_out = pdir / "graph.svg"
        import time, glob, shutil as _sh
        t_before = time.time()

        pmrun(profile, ["visualize", "--filetype", "svg"], label="SVG")

        # Find the SVG pmapper just wrote (newest .svg modified after we started)
        import os as _os
        search_dirs = [
            Path.home() / ".local" / "share" / "principalmapper",
            Path.home() / ".principalmapper",
            Path("."),
        ]
        found_svg = None
        for sdir in search_dirs:
            if not sdir.exists(): continue
            for svg in sdir.rglob("*.svg"):
                if svg.stat().st_mtime >= t_before - 2:
                    found_svg = svg
                    break
            if found_svg: break

        if found_svg:
            _sh.copy2(str(found_svg), str(svg_out))
            ok(f"  SVG → {svg_out}")
        else:
            warn(f"  SVG not found — check {search_dirs[0]}")

        ok(f"Profile {profile} complete → {pdir}")

    log(f"{'═'*50}")
    ok(f"All profiles complete — {outdir}/")

# ─────────────────────────────────────────────────────────────────────────────
# AWS CLI helpers
# ─────────────────────────────────────────────────────────────────────────────
def fetch_admin_policy_principals(profile_name):
    """Get principals with literal AdministratorAccess policy. Silent on failure."""
    try:
        result = subprocess.run(
            ["aws","iam","list-entities-for-policy",
             "--policy-arn","arn:aws:iam::aws:policy/AdministratorAccess",
             "--output","json","--profile",profile_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return set()
        data = json.loads(result.stdout)
        principals = set()
        for u in data.get("PolicyUsers",  []): principals.add(f"user/{u['UserName']}")
        for r in data.get("PolicyRoles",  []): principals.add(f"role/{r['RoleName']}")
        for g in data.get("PolicyGroups", []): principals.add(f"group/{g['GroupName']}")
        if principals:
            ok(f"  AdministratorAccess principals ({profile_name}): {len(principals)} found")
        return principals
    except Exception:
        return set()

# ─────────────────────────────────────────────────────────────────────────────
# Report parsing
# ─────────────────────────────────────────────────────────────────────────────
def read_findings(path):
    try:
        return [l for l in Path(path).read_text(errors="replace").splitlines()
                if l.strip() and not l.startswith("Query:") and l.strip() != "---"]
    except Exception:
        return []

def read_stats(path):
    stats = {}
    try:
        for line in Path(path).read_text(errors="replace").splitlines():
            if "Account" in line:
                m = re.search(r"(\d{10,})", line)
                if m: stats["account_id"] = m.group(1)
            elif "Nodes" in line:
                m = re.search(r"(\d+)\s*\((\d+)\s*admin", line)
                if m: stats["nodes"], stats["admins"] = m.group(1), m.group(2)
            elif "Edges" in line:
                m = re.search(r"(\d+)", line)
                if m: stats["edges"] = m.group(1)
    except Exception:
        pass
    return stats

def extract_principal(line):
    m = re.match(r"^((user|role|group)/[\w\-\.@+=]+)", line.strip())
    return m.group(1) if m else line.split()[0].strip()

def is_managed(name):
    return any(re.search(p, str(name)) for p in AWS_MANAGED_PATTERNS)

def is_svc(name):
    s = str(name)
    return "amazonaws.com" in s and "/" not in s

def parse_dir(outdir):
    profiles = []
    for d in sorted(Path(outdir).iterdir()):
        if not d.is_dir() or d.name.startswith("00_"):
            continue
        p = {
            "name":  d.name,
            "stats": read_stats(d / "02_graph_stats.txt"),
            "raw":   {},
            "admin_policy_principals": fetch_admin_policy_principals(d.name),
        }
        for subdir in ("presets", "queries"):
            dp = d / subdir
            if dp.exists():
                for f in sorted(dp.glob("*.txt")):
                    fds = read_findings(f)
                    if fds: p["raw"][f.stem] = fds
        profiles.append(p)
    return profiles

# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────
def classify(checks):
    groups = []
    iam = checks & IAM_CHECKS
    if len(iam) >= IAM_WILDCARD_THRESHOLD: groups.append(("iam:*","critical",sorted(iam)))
    elif iam:                              groups.append(("IAM (specific)","high",sorted(iam)))
    if checks & S3_CHECKS:
        groups.append(("s3:*" if checks >= S3_CHECKS else "s3 (partial)", "high", sorted(checks & S3_CHECKS)))
    if checks & CRED_CHECKS:    groups.append(("Credential Access","high",sorted(checks & CRED_CHECKS)))
    if checks & COMPUTE_CHECKS: groups.append(("Service Compute Abuse","high",sorted(checks & COMPUTE_CHECKS)))
    if checks & EVASION_CHECKS: groups.append(("Defense Evasion","medium",sorted(checks & EVASION_CHECKS)))
    return groups

def get_technique(mech):
    for label, patterns in TECHNIQUES:
        if any(re.search(p, mech, re.I) for p in patterns):
            return label
    return "Other"

def build_analysis(profile):
    raw              = profile["raw"]
    admin_policy_set = profile.get("admin_policy_principals", set())

    # Per-principal check map
    principal_checks = defaultdict(set)
    for key, findings in raw.items():
        for line in findings:
            pr = extract_principal(line)
            if pr and not is_svc(pr):
                principal_checks[pr].add(key)

    # Multi-hop privesc parser
    pmapper_admins   = set()
    escalation_paths = []
    seen_l = set()
    raw_lines = [l for l in raw.get("privesc_all",[]) + raw.get("privesc_skip",[])
                 if l and l not in seen_l and not seen_l.add(l)]

    current_path = None
    for line in raw_lines:
        if " is an administrative principal" in line:
            if current_path: escalation_paths.append(current_path); current_path = None
            pr = line.replace(" is an administrative principal","").strip()
            pmapper_admins.add(pr)
        elif " can escalate privileges by accessing" in line:
            if current_path: escalation_paths.append(current_path)
            source   = extract_principal(line)
            target_m = re.search(r"accessing the administrative principal (\S+?)[:$\s]", line)
            target   = target_m.group(1).rstrip(":") if target_m else ""
            hops     = []
            if ": " in line:
                inline = line.split(": ",1)[1].strip()
                if inline: hops.append(inline)
            current_path = {
                "source": source, "target": target, "hops": hops,
                "technique": get_technique(hops[0] if hops else ""),
                "managed_source": is_managed(source),
                "managed_target": is_managed(target),
            }
        else:
            if current_path and line.strip():
                current_path["hops"].append(line.strip())
                if len(current_path["hops"]) == 1:
                    current_path["technique"] = get_technique(line)
    if current_path: escalation_paths.append(current_path)

    # Shadow admins
    shadow, seen_shadow = [], set()
    for line in raw.get("wrongadmin",[]):
        pr = extract_principal(line)
        if not pr or is_managed(pr) or pr in seen_shadow: continue
        seen_shadow.add(pr)
        checks = principal_checks.get(pr, set())
        caps   = [CHECK_LABEL[c] for c in sorted(checks) if c in CHECK_LABEL]
        shadow.append({"principal": pr, "capabilities": caps})
    shadow_set = {s["principal"] for s in shadow}

    # Confirmed admins
    real_admin_from_pmapper = {p for p in pmapper_admins if not is_managed(p) and p not in shadow_set}
    confirmed_admins_set    = (admin_policy_set | real_admin_from_pmapper) - shadow_set
    default_managed         = {p for p in pmapper_admins if is_managed(p)}

    # Overly permissive
    op_roles, op_users, op_managed, op_lookup = [], [], [], {}
    GROUP_RANK = {"iam:*":0,"IAM (specific)":0,"Service Compute Abuse":1,
                  "Credential Access":2,"s3:*":3,"s3 (partial)":3,"Defense Evasion":4}
    for principal, checks in sorted(principal_checks.items(), key=lambda x: -len(x[1])):
        groups = classify(checks)
        if not groups: continue
        sev  = ("critical" if any(g[1]=="critical" for g in groups) else
                "high"     if any(g[1]=="high"     for g in groups) else "medium")
        caps = [CHECK_LABEL[c] for c in sorted(checks) if c in CHECK_LABEL]
        entry = {"principal":principal,"groups":groups,"severity":sev,
                 "capabilities":caps,"checks":checks,"managed":is_managed(principal)}
        op_lookup[principal] = entry
        if   is_managed(principal):            op_managed.append(entry)
        elif principal.startswith("role/"):    op_roles.append(entry)
        else:                                  op_users.append(entry)

    sev_rank = {"critical":0,"high":1,"medium":2}
    for lst in (op_roles, op_users):
        lst.sort(key=lambda x:(
            min((GROUP_RANK.get(g[0],9) for g in x["groups"]), default=9),
            sev_rank.get(x["severity"],9)
        ))

    op_critical_set  = {x["principal"] for x in op_roles+op_users if x["severity"]=="critical"}
    already_reported = confirmed_admins_set | shadow_set | op_critical_set

    # Confirmed admin entries for display
    confirmed_admin_entries = []
    for pr in sorted(confirmed_admins_set):
        entry = op_lookup.get(pr, {
            "principal": pr, "groups":[("AdministratorAccess","critical",[])],
            "severity":"critical","capabilities":["Full administrator access"],"managed":False
        })
        confirmed_admin_entries.append(entry)

    op_display = [x for x in op_roles+op_users
                  if x["severity"] != "critical"
                  and x["principal"] not in shadow_set
                  and x["principal"] not in confirmed_admins_set]

    technique_groups = defaultdict(list)
    for path in escalation_paths:
        technique_groups[path["technique"]].append(path)

    chain_paths = [p for p in escalation_paths if p["source"] not in op_critical_set]

    # S3 / Cred / Evasion — deduplicated
    def dedup_principals(lines):
        return list(dict.fromkeys(
            p for p in (extract_principal(l) for l in lines)
            if p not in already_reported
        ))

    return {
        "confirmed_admins":     confirmed_admin_entries,
        "confirmed_admins_set": confirmed_admins_set,
        "default_managed":      sorted(default_managed),
        "shadow":               shadow,
        "shadow_set":           shadow_set,
        "op_display":           op_display,
        "escalation_paths":     escalation_paths,
        "technique_groups":     dict(technique_groups),
        "chain_paths":          chain_paths,
        "admin_policy_set":     admin_policy_set,
        "s3_get":     dedup_principals(raw.get("s3_get_object",[])),
        "s3_policy":  dedup_principals(raw.get("s3_put_bucket_policy",[])),
        "cred_sm":    dedup_principals(raw.get("secretsmanager_get",[])),
        "cred_ssm":   dedup_principals(raw.get("ssm_get_parameter",[])+raw.get("ssm_get_parameters",[])),
        "cloudtrail": dedup_principals(raw.get("cloudtrail_stop",[])+raw.get("cloudtrail_delete",[])),
        "guardduty":  dedup_principals(raw.get("guardduty_delete",[])),
    }

# ─────────────────────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────────────────────
def e(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def sev_badge(sev):
    labels = {"critical":"Critical","high":"High","medium":"Medium","info":"Informational"}
    return f'<span class="sev-badge {sev}">{labels.get(sev,sev.title())}</span>'

def copy_btn(items, label="⎘ Copy"):
    return f'<button class="cbtn" onclick="cb(this)" data-v="{e(chr(10).join(items))}">{label}</button>'

def principal_tag(p, sev="critical"):
    return f'<code class="hl-principal {sev}">{e(p)}</code>'

def managed_note(msg=""):
    msg = msg or "These are AWS-managed roles expected to have elevated permissions. Verify access is appropriately restricted."
    return f'<div class="managed-note"><span class="mi">ⓘ</span> {e(msg)}</div>'

def finding(title, severity, impact, description_html, pid=""):
    fid = (pid+"_" if pid else "") + re.sub(r"\W","_",title)
    return f"""
<div class="finding" id="f-{fid}">
  <div class="finding-hdr" onclick="togF('{fid}')">
    <div class="finding-hdr-l">
      <span class="fchev" id="fc-{fid}">▶</span>
      <h2 class="ftitle">{e(title)}</h2>
    </div>
    {sev_badge(severity)}
  </div>
  <div class="fbody hidden" id="fb-{fid}">
    <div class="fsec"><h3>Severity</h3>{sev_badge(severity)}</div>
    <div class="fsec"><h3>Impact</h3><p>{e(impact)}</p></div>
    <div class="fsec"><h3>Description</h3>{description_html}</div>
  </div>
</div>"""

# ─────────────────────────────────────────────────────────────────────────────
# Section renderers
# ─────────────────────────────────────────────────────────────────────────────
def render_admin(a, pid=""):
    real = [x for x in a["confirmed_admins"] if not is_managed(x["principal"])]
    if not real: return ""
    all_p = [x["principal"] for x in real]
    desc  = f"<p>{copy_btn(all_p)}</p>"
    for x in real:
        desc += (f"<div class='op-entry'><div class='op-entry-hdr'>"
                 f"{principal_tag(x['principal'],'critical')}"
                 f"<span class='inline-badge critical'>AdministratorAccess</span>"
                 f"</div></div>")
    return finding("Roles with Administrator Access","critical",
                   "Roles with AdministratorAccess have unrestricted access to all AWS services "
                   "and resources. A compromised credential results in full account takeover.",
                   desc, pid)


def render_default_managed(a, pid=""):
    roles = a["default_managed"]
    if not roles: return ""
    desc  = ("<p>The following AWS-managed roles were identified as administrative principals. "
             "These are created by AWS services such as Control Tower, StackSets, and SSO. "
             "While expected to be privileged, the ability for lower-privilege principals to "
             "reach them should be reviewed.</p>")
    desc += f"<p>{copy_btn(list(roles))}</p>"
    for r in sorted(roles):
        desc += (f"<div class='op-entry mgd-entry'><div class='op-entry-hdr'>"
                 f"{principal_tag(r,'medium')}"
                 f"<span class='managed-tag'>AWS Managed</span>"
                 f"</div></div>")
    return finding("Default AWS Managed Roles","medium",
                   "Default AWS managed roles carry elevated permissions by design. Review trust "
                   "policies to confirm access is restricted to authorised principals only.",
                   desc, pid)


def render_shadow(a, pid=""):
    shadow = a["shadow"]
    if not shadow: return ""
    sorted_shadow = sorted(shadow, key=lambda x: -len(x["capabilities"]))
    top       = sorted_shadow[:5]
    remaining = len(sorted_shadow) - len(top)
    all_p     = [s["principal"] for s in shadow]
    desc      = ("<p>A shadow admin holds administrator-equivalent permissions without the "
                 "<code>AdministratorAccess</code> policy attached, making them invisible to "
                 "standard IAM audits that check only policy names.</p>")
    desc     += f"<p>{copy_btn(all_p)}</p>"
    for s in top:
        caps     = s["capabilities"][:6]
        caps_html= "".join(f"<li>{e(c)}</li>" for c in caps) if caps \
                   else "<li>Verify attached policies — pmapper identified effective admin-level access</li>"
        desc    += (f"<div class='op-entry'><div class='op-entry-hdr'>"
                    f"{principal_tag(s['principal'],'critical')}"
                    f"<span class='inline-badge critical'>Shadow Admin</span></div>"
                    f"<p class='op-entry-label'>Effective capabilities:</p>"
                    f"<ul class='cap-list'>{caps_html}</ul></div>")
    if remaining > 0:
        rest = [s["principal"] for s in sorted_shadow[5:]]
        desc += (f"<div class='op-entry mgd-entry'><div class='op-entry-hdr'>"
                 f"<span class='op-entry-label'>{remaining} additional shadow admin"
                 f"{'s' if remaining>1 else ''}: </span>"
                 f"{copy_btn(rest,'⎘ Copy Remaining')}</div></div>")
    return finding("Shadow Admins","critical",
                   "Shadow admins have effective administrator access but lack the "
                   "AdministratorAccess policy, making them invisible to standard IAM audits.",
                   desc, pid)


def render_op(a, pid=""):
    entries = a["op_display"]
    if not entries: return ""
    GROUP_RANK = {"iam:*":0,"IAM (specific)":0,"Service Compute Abuse":1,
                  "Credential Access":2,"s3:*":3,"s3 (partial)":3,"Defense Evasion":4}
    all_p = [x["principal"] for x in entries]
    desc  = ("<p>The following principals have permissions significantly broader than required, "
             "excluding those already reported as administrators or shadow admins. "
             "IAM-related permissions are listed first as they carry the highest escalation risk.</p>")
    desc += f"<p>{copy_btn(all_p)}</p>"
    for x in entries:
        sg    = sorted(x["groups"], key=lambda g: GROUP_RANK.get(g[0],9))
        gtags = "".join(f'<span class="inline-badge {g[1]}">{e(g[0])}</span>' for g in sg)
        caps  = "".join(f"<li>{e(c)}</li>" for c in x["capabilities"])
        desc += (f"<div class='op-entry'><div class='op-entry-hdr'>"
                 f"{principal_tag(x['principal'],x['severity'])}{gtags}</div>"
                 f"<p class='op-entry-label'>With these permissions an attacker can:</p>"
                 f"<ul class='cap-list'>{caps}</ul></div>")
    sev = "high" if any(x["severity"]=="high" for x in entries) else "medium"
    return finding("Overly Permissive IAM Principals", sev,
                   "Principals with excessive permissions increase the blast radius of any "
                   "credential compromise. A single stolen session gives all listed capabilities.",
                   desc, pid)


def render_privesc(a, pid=""):
    tgroups    = a.get("technique_groups",{})
    chain_paths= a.get("chain_paths",[])
    all_paths  = a.get("escalation_paths",[])

    if not all_paths:
        return finding("Privilege Escalation","info",
                       "No privilege escalation paths identified.",
                       "<p>PMapper found no escalation paths in this account.</p>", pid)

    TECH_ORDER = ["Direct STS AssumeRole","CodeBuild Project Abuse","Lambda Function Code Update",
                  "Access Key Creation","Policy Attachment","EC2 Instance Profile",
                  "CloudFormation Stack","Glue Job","Role Trust Policy Modification","Other"]

    chain_sources    = {p["source"] for p in chain_paths}
    ordered_techs    = sorted(tgroups.keys(), key=lambda t: TECH_ORDER.index(t) if t in TECH_ORDER else 99)

    def hop_html(path, sev="critical"):
        h  = "<div class='hop-chain'>"
        h += f"<div class='hop-row'>{principal_tag(path['source'], sev)}</div>"
        for hop in path.get("hops",[]):
            h += f"<div class='hop-row'><span class='hop-arrow'>&#8627;</span><span class='hop-text'>{e(hop)}</span></div>"
        if path["target"]:
            h += (f"<div class='hop-row'><span class='hop-arrow'>&#8627;</span>"
                  f"{principal_tag(path['target'],'high')} <span class='admin-label'>Admin</span></div>")
        h += "</div>"
        return h

    def technique_block(technique, paths):
        real    = [p for p in paths if not p["managed_source"]]
        managed = [p for p in paths if p["managed_source"]]
        out     = f"<div class='privesc-technique'><div class='technique-label'>{e(technique)}</div>"
        if real:
            by_target = defaultdict(list)
            for p in real: by_target[p["target"]].append(p)
            for target, tpaths in by_target.items():
                if len(tpaths) == 1:
                    out += f"<div class='path-block'>{hop_html(tpaths[0])}</div>"
                else:
                    all_src = [p["source"] for p in tpaths]
                    ex      = tpaths[0]
                    chips   = "".join(f"{principal_tag(s,'critical')} " for s in all_src[:6])
                    more    = f'<span class="more-chip">+{len(all_src)-6} more</span>' if len(all_src)>6 else ""
                    out += (f"<div class='path-block'>"
                            f"<p class='path-multi-note'>The following {len(all_src)} principals "
                            f"share the same escalation path. "
                            f"Example using {principal_tag(ex['source'],'critical')}:</p>"
                            f"<div class='path-chips'>{chips}{more} {copy_btn(all_src)}</div>"
                            f"{hop_html(ex)}</div>")
        if managed:
            out += "<div class='path-block mgd-path'>"
            for p in managed: out += hop_html(p, "medium")
            out += "</div>"
            out += managed_note("These paths involve AWS-managed roles. Verify whether this access is intentional.")
        out += "</div>"
        return out

    impact = ("Multiple IAM principals can escalate to full administrative access through one "
              "or more steps, exploiting overly permissive IAM configurations without requiring "
              "any vulnerability.")
    desc   = ("<p>During testing, PMapper was used to analyse the IAM permission graph. "
              "Escalation paths are grouped by technique. Where multiple principals share the "
              "same path, they are collapsed with one representative example shown.</p>")

    # Direct escalation
    direct = {t:[p for p in paths if p["source"] not in chain_sources] for t,paths in tgroups.items()}
    direct = {t:p for t,p in direct.items() if p}
    if direct:
        desc += "<div class='privesc-group-label'>Direct Privilege Escalation</div>"
        for t in ordered_techs:
            if t in direct: desc += technique_block(t, direct[t])

    # Chained exploit
    chained = {t:[p for p in paths if p["source"] in chain_sources] for t,paths in tgroups.items()}
    chained = {t:p for t,p in chained.items() if p}
    if chained:
        desc += ("<div class='privesc-group-label chain-label'>Chained Exploit — Low-Privilege to Admin</div>"
                 "<p class='chain-desc'>These principals do not have direct <code>iam:*</code> access "
                 "but can reach an administrative role through one or more intermediate steps.</p>")
        for t in ordered_techs:
            if t in chained: desc += technique_block(t, chained[t])
    elif not direct:
        desc += "<p><strong>No chaining observed.</strong></p>"

    return finding("Privilege Escalation","critical",impact,desc,pid)

# ─────────────────────────────────────────────────────────────────────────────
# CSS + JS
# ─────────────────────────────────────────────────────────────────────────────
CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
:root{
  --bg:#f5f7fb;--bg2:#fff;--bg3:#f0f2f8;--bg4:#e8ecf5;
  --bd:#dde2f0;--bd2:#c4ccdf;
  --tx:#1e2540;--tx2:#667299;--txb:#0a1020;
  --cr:#c0112a;--cr2:#fff0f2;--cr3:#fac8cf;
  --hi:#b04400;--hi2:#fff6f0;--hi3:#f8d4be;
  --md:#8a6000;--md2:#fefaee;--md3:#f0e098;
  --ok:#1a8050;--ok2:#eefaf4;--ok3:#a0e4c0;
  --ac:#1848c8;--ac2:#eef2ff;--ac3:#b0c4f8;
  --inf:#3060b0;--inf2:#eef4ff;--inf3:#b8d0f8;
  --mono:'JetBrains Mono',monospace;--body:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--body);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.7}
code{font-family:var(--mono);font-size:12px;background:var(--bg4);padding:1px 5px;border-radius:3px;color:var(--ac)}
p{margin-bottom:8px} p:last-child{margin-bottom:0}
strong{color:var(--txb);font-weight:600}

.rpt-hdr{background:var(--bg2);border-bottom:2px solid var(--bd);padding:18px 32px}
.rpt-hdr-inner{max-width:940px;margin:0 auto}
.rpt-lbl{font-family:var(--mono);font-size:10px;color:var(--ac);letter-spacing:2px;text-transform:uppercase;margin-bottom:3px}
.rpt-title{font-size:20px;font-weight:700;color:var(--txb)}
.rpt-meta{font-size:11px;color:var(--tx2);margin-top:3px;font-family:var(--mono)}

.main{max-width:940px;margin:0 auto;padding:22px 32px}

.profile-section{margin-bottom:20px}
.profile-hdr{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:var(--bg2);border:1px solid var(--bd);border-radius:7px;cursor:pointer;user-select:none;transition:background .15s}
.profile-hdr:hover{background:var(--bg3)}
.profile-hdr-l{display:flex;align-items:center;gap:10px}
.pchev{font-size:11px;color:var(--tx2);transition:transform .2s}
.pchev.op{transform:rotate(90deg)}
.pname{font-family:var(--mono);font-size:14px;font-weight:700;color:var(--txb);display:block}
.pmeta{font-size:11px;color:var(--tx2);font-family:var(--mono);display:block;margin-top:1px}
.pbody{padding:12px 0 0;display:flex;flex-direction:column;gap:10px}
.pbody.hidden{display:none}

.finding{background:var(--bg2);border:1px solid var(--bd);border-radius:7px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.finding-hdr{display:flex;justify-content:space-between;align-items:center;padding:11px 15px;cursor:pointer;user-select:none}
.finding-hdr:hover{background:var(--bg3)}
.finding-hdr-l{display:flex;align-items:center;gap:8px}
.fchev{font-size:11px;color:var(--tx2);transition:transform .2s;flex-shrink:0}
.fchev.op{transform:rotate(90deg)}
h2.ftitle{font-size:14px;font-weight:700;color:var(--txb)}
.fbody{display:flex;flex-direction:column;border-top:1px solid var(--bd)}
.fbody.hidden{display:none}
.fsec{padding:12px 16px;border-bottom:1px solid var(--bg3)}
.fsec:last-child{border-bottom:none}
h3{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--tx2);margin-bottom:7px;font-family:var(--mono)}

.sev-badge{font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 9px;border-radius:4px;border:1px solid;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.sev-badge.critical{background:var(--cr2);border-color:var(--cr3);color:var(--cr)}
.sev-badge.high{background:var(--hi2);border-color:var(--hi3);color:var(--hi)}
.sev-badge.medium{background:var(--md2);border-color:var(--md3);color:var(--md)}
.sev-badge.info{background:var(--inf2);border-color:var(--inf3);color:var(--inf)}

.inline-badge{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;border:1px solid}
.inline-badge.critical{background:var(--cr2);border-color:var(--cr3);color:var(--cr)}
.inline-badge.high{background:var(--hi2);border-color:var(--hi3);color:var(--hi)}
.inline-badge.medium{background:var(--md2);border-color:var(--md3);color:var(--md)}

code.hl-principal{font-family:var(--mono);font-size:12px;font-weight:700;padding:2px 7px;border-radius:4px;border:1px solid}
code.hl-principal.critical{background:var(--cr2);border-color:var(--cr3);color:var(--cr)}
code.hl-principal.high{background:var(--hi2);border-color:var(--hi3);color:var(--hi)}
code.hl-principal.medium{background:var(--md2);border-color:var(--md3);color:var(--md)}

.op-entry{background:var(--bg3);border:1px solid var(--bd);border-radius:5px;padding:10px 13px;margin-top:7px}
.op-entry.mgd-entry{opacity:.75;background:var(--inf2);border-color:var(--inf3)}
.op-entry-hdr{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:5px}
.op-entry-label{font-size:12px;color:var(--tx2);margin-bottom:4px;font-style:italic}
.cap-list{padding-left:0;list-style:none;display:flex;flex-direction:column;gap:3px;margin-top:4px}
.cap-list li{font-size:13px;color:var(--tx);padding:3px 8px;display:flex;gap:7px}
.cap-list li::before{content:"→";color:var(--cr);font-family:var(--mono);font-size:11px;flex-shrink:0;margin-top:2px}

.privesc-technique{background:var(--bg3);border:1px solid var(--bd);border-radius:6px;padding:12px 14px;margin-top:10px}
.technique-label{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--ac);background:var(--ac2);border:1px solid var(--ac3);padding:3px 10px;border-radius:4px;display:inline-block;margin-bottom:10px}
.privesc-group-label{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--txb);text-transform:uppercase;letter-spacing:.8px;margin:14px 0 2px;padding:6px 10px;background:var(--bg4);border-radius:4px}
.chain-label{color:var(--cr)}
.chain-desc{font-size:13px;color:var(--tx2);margin-bottom:8px}
.path-block{background:var(--bg2);border:1px solid var(--bd);border-radius:5px;padding:10px 13px;margin-top:6px}
.path-block.mgd-path{background:var(--inf2);border-color:var(--inf3);opacity:.8}
.path-multi-note{font-size:13px;color:var(--tx);margin-bottom:7px}
.path-chips{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px}
.more-chip{font-family:var(--mono);font-size:10px;color:var(--tx2);padding:2px 4px}
.hop-chain{display:flex;flex-direction:column;gap:4px;margin-top:4px}
.hop-row{display:flex;align-items:flex-start;gap:8px;padding:2px 0}
.hop-arrow{color:var(--ac);font-family:var(--mono);font-size:14px;flex-shrink:0;min-width:18px}
.hop-text{color:var(--tx);font-family:var(--mono);font-size:11px;word-break:break-all;line-height:1.6}
.admin-label{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--cr);background:var(--cr2);border:1px solid var(--cr3);padding:1px 5px;border-radius:3px;margin-left:4px;white-space:nowrap}

.managed-note{background:var(--inf2);border:1px solid var(--inf3);border-radius:5px;padding:9px 13px;font-size:13px;color:var(--inf);margin-top:10px;line-height:1.6}
.mi{font-weight:700;margin-right:4px}
.managed-tag{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;background:var(--inf2);border:1px solid var(--inf3);border-radius:3px;color:var(--inf)}
.cbtn{font-family:var(--mono);font-size:10px;padding:3px 9px;background:var(--ac2);border:1px solid var(--ac3);color:var(--ac);border-radius:4px;cursor:pointer;transition:all .15s;white-space:nowrap;vertical-align:middle;margin-left:4px}
.cbtn:hover{background:var(--ac3)}
.cbtn.ok{background:var(--ok2);border-color:var(--ok3);color:var(--ok)}
.no-findings{text-align:center;padding:20px;color:var(--ok);font-family:var(--mono);font-size:12px;background:var(--ok2);border:1px solid var(--ok3);border-radius:5px}
.footer{text-align:center;padding:16px;font-size:11px;color:var(--tx2);border-top:1px solid var(--bd);margin-top:24px;font-family:var(--mono)}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:3px}
@media print{.cbtn,.pchev,.fchev{display:none}.fbody,.pbody{display:flex!important}body{background:#fff}}
"""

JS = """
function togP(id){document.getElementById('pb-'+id).classList.toggle('hidden');document.getElementById('pc-'+id).classList.toggle('op');}
function togF(id){document.getElementById('fb-'+id).classList.toggle('hidden');document.getElementById('fc-'+id).classList.toggle('op');}
function cb(btn){navigator.clipboard.writeText(btn.getAttribute('data-v')).then(()=>{btn.classList.add('ok');const o=btn.textContent;btn.textContent='✓ Copied';setTimeout(()=>{btn.classList.remove('ok');btn.textContent=o;},1500);});}
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.pbody').forEach(b=>togP(b.id.replace('pb-','')));
  document.querySelectorAll('.fbody').forEach(b=>togF(b.id.replace('fb-','')));
});
"""

# ─────────────────────────────────────────────────────────────────────────────
# Report render
# ─────────────────────────────────────────────────────────────────────────────
def render_html(profiles, analyses, outdir):
    run_date = datetime.now().strftime("%d %b %Y  %H:%M")
    sections = ""

    for profile, analysis in zip(profiles, analyses):
        name  = profile["name"]
        stats = profile["stats"]
        pid   = re.sub(r"\W","_",name)

        body = "\n".join(filter(None,[
            render_admin(analysis, pid),
            render_default_managed(analysis, pid),
            render_shadow(analysis, pid),
            render_op(analysis, pid),
            render_privesc(analysis, pid),
        ]))
        if not body:
            body = '<div class="no-findings">✓ No findings identified for this profile</div>'

        sections += (
            f'<div class="profile-section">'
            f'<div class="profile-hdr" onclick="togP(\'{pid}\')">'
            f'<div class="profile-hdr-l">'
            f'<span class="pchev" id="pc-{pid}">▶</span>'
            f'<div><span class="pname">{e(name)}</span>'
            f'<span class="pmeta">Account: <code>{e(stats.get("account_id","—"))}</code>'
            f' &nbsp;·&nbsp; {stats.get("nodes","?")} nodes'
            f' &nbsp;·&nbsp; {stats.get("admins","?")} admins</span>'
            f'</div></div></div>'
            f'<div class="pbody hidden" id="pb-{pid}">{body}</div>'
            f'</div>'
        )

    return (
        f'<!DOCTYPE html><html lang="en"><head>'
        f'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>IAM Report — {e(run_date)}</title>'
        f'<style>{CSS}</style></head><body>'
        f'<div class="rpt-hdr"><div class="rpt-hdr-inner">'
        f'<div class="rpt-lbl">AWS IAM Security Assessment</div>'
        f'<div class="rpt-title">IAM Privilege Review Report</div>'
        f'<div class="rpt-meta">{e(run_date)} &nbsp;·&nbsp; '
        f'{len(profiles)} profile{"s" if len(profiles)!=1 else ""}'
        f' &nbsp;·&nbsp; PMapper</div>'
        f'</div></div>'
        f'<div class="main">{sections}</div>'
        f'<div class="footer">Generated {e(run_date)} &nbsp;·&nbsp; 100% local — no data transmitted</div>'
        f'<script>{JS}</script></body></html>'
    )

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    profiles = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_PROFILES
    if not profiles:
        print("Usage: python3 pmapper_iam.py [profile1 profile2 ...]")
        print("       or set DEFAULT_PROFILES at the top of the script")
        sys.exit(1)

    print(f"\n{'═'*55}")
    print(f"  PMapper IAM Review + Report")
    print(f"  Profiles: {', '.join(profiles)}")
    print(f"{'═'*55}")

    outdir = f"pmapper_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Phase 1: run pmapper
    log("Phase 1 — Running pmapper queries")
    run_review(profiles, outdir)

    # Phase 2: generate report
    log("Phase 2 — Generating HTML report")
    parsed   = parse_dir(outdir)
    if not parsed:
        err("No profile directories found in output — nothing to report")
        sys.exit(1)
    analyses = [build_analysis(p) for p in parsed]
    html     = render_html(parsed, analyses, outdir)
    report   = os.path.join(outdir, "report.html")
    Path(report).write_text(html, encoding="utf-8")

    print(f"\n{'═'*55}")
    ok(f"Output:  {outdir}/")
    ok(f"Report:  {report}")
    print(f"{'═'*55}\n")
    print(f"  Open:  firefox {report}")
    print(f"         xdg-open {report}")
    print()

if __name__ == "__main__":
    main()
