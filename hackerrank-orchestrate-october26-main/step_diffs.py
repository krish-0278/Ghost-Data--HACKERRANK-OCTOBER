import os, sys, csv, json

repo_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(repo_root, 'code'))
from main import DeletionAuditEngine

dataset_dir = os.path.join(repo_root, 'dataset')
engine = DeletionAuditEngine(dataset_dir)

sample_out = {}
with open(os.path.join(dataset_dir, 'sample_output.csv'), 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        sample_out[r['case_id']] = (r['deletion_status'], json.loads(r['steps_json']))

with open(os.path.join(dataset_dir, 'sample_deletion_requests.csv'), 'r', encoding='utf-8') as f:
    for r in csv.DictReader(f):
        cid = r['case_id']
        gt_status, gt_steps = sample_out[cid]
        pred_status, pred_steps = engine.audit_case(r)
        
        if pred_steps != gt_steps:
            print(f"\n==================== {cid} (GT: {gt_status}, PRED: {pred_status}) ====================")
            print("GT STEPS:")
            for s in gt_steps:
                print(f"  {s.get('phase')} | {s.get('system_id')} | {s.get('resource_id')} | {s.get('operation')} | {s.get('state')} | ev={s.get('evidence_id')}")
            print("PRED STEPS:")
            for s in pred_steps:
                print(f"  {s.get('phase')} | {s.get('system_id')} | {s.get('resource_id')} | {s.get('operation')} | {s.get('state')} | ev={s.get('evidence_id')}")
