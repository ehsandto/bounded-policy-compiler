import ast
import hashlib
import itertools
import json
import re
from pathlib import Path
from types import SimpleNamespace
import pytest

TREE=ast.parse(Path('contracts/BoundedPolicyCompiler.py').read_text())
NS={'hashlib':hashlib,'json':json,'re':re,'LABELS':('ALLOW','DENY','CONFLICT','UNKNOWN')}
exec(compile(ast.Module(body=[n for n in TREE.body if isinstance(n,ast.FunctionDef)
    and n.name not in ('fail','fetch_source')],type_ignores=[]),'actual-functions','exec'),NS)
PREDICATES="staff=The operator is a staff member|supervised=A qualified supervisor is present|revoked=The operator's workshop access is revoked"
ACTION='Use the workshop laser cutter'
GOOD=['DENY','ALLOW','ALLOW','ALLOW','DENY','DENY','DENY','DENY']
UNRESOLVED=['UNKNOWN']*4+['DENY']*4
BODY=Path('examples/workshop-policy.txt').read_bytes()


@pytest.fixture
def compiler(direct_vm,direct_deploy,direct_alice):
    direct_vm.sender=direct_alice
    return direct_deploy('contracts/BoundedPolicyCompiler.py')


def compile_one(compiler,vm,nonce='demo',table=GOOD,http=200,bad_hash=False,body=BODY):
    vm.clear_mocks()
    vm.mock_web(r'.*/workshop-policy\.txt',{'status':http,'body':body})
    if table is not None:vm.mock_llm(r'(?s).*BOUNDED POLICY COMPILATION.*',json.dumps({'table':table}))
    return compiler.compile_policy(nonce,ACTION,PREDICATES,'ehsandto','bounded-policy-compiler','a'*40,
        'examples/workshop-policy.txt','f'*64 if bad_hash else hashlib.sha256(BODY).hexdigest())


def artifact_for(compiler,attempt):
    record=compiler.get_attempt(attempt)
    key=record['report']['binding']['artifact']
    return key,compiler.get_artifact(key)


def test_real_evidence_body_compiles_all_cells_and_root_bound_partial_queries(compiler,direct_vm):
    attempt=compile_one(compiler,direct_vm)
    record=compiler.get_attempt(attempt)
    assert record['status']=='COMPILED'
    root=record.pop('root');assert NS['digest'](record)==root
    key,artifact=artifact_for(compiler,attempt)
    assert artifact['source']['body'].encode()==BODY and artifact['table']==GOOD
    assert artifact['source']['hash']==hashlib.sha256(BODY).hexdigest()
    assert key==NS['digest'](artifact['config'])
    body=dict(artifact);root=body.pop('root');assert root==NS['digest'](body)
    assert compiler.simulate(key,root,5,1)['decision']=='ALLOW'  # staff true, revoked false, supervision unknown
    assert compiler.simulate(key,root,4,4)['decision']=='DENY'  # revoked, other conditions unknown
    assert compiler.simulate(key,root,4,0)['decision']=='UNRESOLVED'  # nonrevoked alone insufficient
    assert compiler.simulate(key,root,0,0)['hypothetical_only'] is True
    with direct_vm.expect_revert('Artifact root mismatch'):compiler.simulate(key,'f'*64,5,1)


@pytest.mark.parametrize('table',[[label]*8 for label in NS['LABELS']])
def test_consequential_ai_changes_compiled_function(compiler,direct_vm,table):
    attempt=compile_one(compiler,direct_vm,table=table)
    key,artifact=artifact_for(compiler,attempt)
    result=compiler.simulate(key,artifact['root'],0,0)
    expected=table[0] if table[0] in ('ALLOW','DENY') else 'UNRESOLVED'
    assert result['decision']==expected
    assert result['has_conflict']==(table[0]=='CONFLICT')
    assert result['has_unknown']==(table[0]=='UNKNOWN')


def test_unknown_cells_do_not_disable_known_safe_or_denied_subspaces(compiler,direct_vm):
    attempt=compile_one(compiler,direct_vm,table=UNRESOLVED)
    key,artifact=artifact_for(compiler,attempt)
    assert compiler.simulate(key,artifact['root'],4,4)['decision']=='DENY'
    result=compiler.simulate(key,artifact['root'],4,0)
    assert result['decision']=='UNRESOLVED' and result['has_unknown']


@pytest.mark.parametrize('kind',['hash','http','encoding','oversize'])
def test_failed_acquisition_creates_no_callable_artifact(compiler,direct_vm,kind):
    body=b'\xff' if kind=='encoding' else b'x'*8193 if kind=='oversize' else BODY
    attempt=compile_one(compiler,direct_vm,table=None,http=503 if kind=='http' else 200,bad_hash=kind=='hash',body=body)
    record=compiler.get_attempt(attempt)
    assert record['status']=='HELD' and record['report']['table']==[]
    key=record['report']['binding']['artifact']
    with direct_vm.expect_revert('No compiled artifact'):compiler.get_artifact(key)
    with direct_vm.expect_revert('No compiled artifact'):compiler.simulate(key,'f'*64,0,0)


def test_failed_attempt_cannot_poison_shared_content_address(compiler,direct_vm):
    held=compile_one(compiler,direct_vm,nonce='held',table=None,http=503)
    successful=compile_one(compiler,direct_vm,nonce='retry')
    assert compiler.get_attempt(held)['report']['binding']['artifact']==compiler.get_attempt(successful)['report']['binding']['artifact']
    assert compiler.get_attempt(held)['status']=='HELD'
    assert compiler.get_attempt(successful)['status']=='COMPILED'


def test_replay_dedup_and_immutable_artifact(compiler,direct_vm,direct_bob):
    attempt=compile_one(compiler,direct_vm)
    key,artifact=artifact_for(compiler,attempt)
    with direct_vm.expect_revert('Attempt nonce used'):compile_one(compiler,direct_vm)
    with direct_vm.expect_revert('Artifact already compiled'):compile_one(compiler,direct_vm,nonce='different')
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Artifact already compiled'):compile_one(compiler,direct_vm,nonce='bob')
    assert compiler.get_artifact(key)==artifact


@pytest.mark.parametrize('raw',[[],['ALLOW']*7,['ALLOW']*9,[True]*8,['allow']*8])
def test_incomplete_or_malformed_ai_table_cannot_compile(compiler,direct_vm,raw):
    with direct_vm.expect_revert('Invalid compiled truth table'):compile_one(compiler,direct_vm,table=raw)


@pytest.mark.parametrize('raw',['','staff=Short','staff=The operator is staff|staff=The operator is supervised',
    'staff=Same predicate text|other=Same predicate text','bad-id=The operator is staff',
    '|'.join('x'+str(i)+'=A sufficiently long predicate' for i in range(5))])
def test_bad_predicate_schema(raw):
    with pytest.raises(ValueError):NS['predicates_from'](raw)


@pytest.mark.parametrize('path',['../secret.txt','/a.txt','a//b.txt','a/./b.txt','https://host/a.txt','a%2fb.txt'])
def test_path_escape_rejected(path):
    with pytest.raises(ValueError):NS['source_spec']('owner','repo','a'*40,path,'f'*64)


@pytest.mark.parametrize('known,value',[(0,1),(-1,0),(8,0),(7,8),(True,0),(1,True)])
def test_invalid_partial_assignments(known,value):
    with pytest.raises(ValueError):NS['simulate_table'](GOOD,3,known,value)


def test_exhaustive_two_predicate_tables_and_all_partial_contexts():
    count=0
    for table in itertools.product(NS['LABELS'],repeat=4):
        for conditions in itertools.product((None,False,True),repeat=2):
            known=sum(1<<i for i,c in enumerate(conditions) if c is not None)
            value=sum(1<<i for i,c in enumerate(conditions) if c is True)
            result=NS['simulate_table'](list(table),2,known,value)
            completions=[i for i in range(4) if all(c is None or bool(i&(1<<j))==c for j,c in enumerate(conditions))]
            labels=[table[i] for i in completions]
            assert result['completions']==completions
            assert (result['decision']=='ALLOW')==all(label=='ALLOW' for label in labels)
            assert (result['decision']=='DENY')==all(label=='DENY' for label in labels)
            assert result['has_conflict']==any(label=='CONFLICT' for label in labels)
            assert result['has_unknown']==any(label=='UNKNOWN' for label in labels)
            count+=1
    assert count==2304


def test_four_predicate_bit_order_and_complete_coverage():
    predicates=NS['predicates_from']('a=Predicate number one|b=Predicate number two|c=Predicate number three|d=Predicate number four')
    rows=NS['assignments'](predicates)
    assert len(rows)==16 and rows[8]['conditions']=={'a':False,'b':False,'c':False,'d':True}
    table=['ALLOW' if i&8 else 'DENY' for i in range(16)]
    for conditions in itertools.product((None,False,True),repeat=4):
        known=sum(1<<i for i,c in enumerate(conditions) if c is not None)
        value=sum(1<<i for i,c in enumerate(conditions) if c is True)
        result=NS['simulate_table'](table,4,known,value)
        expected='UNRESOLVED' if conditions[3] is None else 'ALLOW' if conditions[3] else 'DENY'
        assert result['decision']==expected


def test_actual_validator_recompiles_every_cell_and_binding():
    cls=next(n for n in TREE.body if isinstance(n,ast.ClassDef))
    method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='compile_policy')
    fn=next(n for n in method.body if isinstance(n,ast.FunctionDef) and n.name=='validator')
    class Return:
        def __init__(self,data):self.calldata=data
    expected={'binding':{'attempt':'a'},'config':{'action':ACTION},'source':{'body':'observed policy'},'table':GOOD}
    calls=[]
    def observe():calls.append(1);return expected
    ns=dict(NS,gl=SimpleNamespace(vm=SimpleNamespace(Return=Return)),observe=observe)
    exec(compile(ast.Module(body=[fn],type_ignores=[]),'actual-validator','exec'),ns)
    assert ns['validator'](Return(expected)) and calls==[1]
    for field,value in [('table',['ALLOW']*8),('source',{'body':'substitution'}),('config',{'action':'Other action'}),('binding',{'attempt':'other'})]:
        assert not ns['validator'](Return(dict(expected,**{field:value})))
    assert not ns['validator'](object())


@pytest.mark.parametrize('field',['binding','config','source','table'])
def test_post_consensus_binding_checks(compiler,direct_vm,monkeypatch,field):
    from genlayer import gl
    original=gl.vm.run_nondet_unsafe
    def forged(observe,validator):
        report=json.loads(json.dumps(original(observe,validator)))
        if field=='binding':report[field]['nonce']='forged'
        elif field=='config':report[field]['action']='Other action'
        elif field=='source':report[field]['body']='substitution'
        else:report[field]=['ALLOW']
        return report
    monkeypatch.setattr(gl.vm,'run_nondet_unsafe',forged)
    with direct_vm.expect_revert('Invalid compilation report'):compile_one(compiler,direct_vm)


def test_duplicate_json_keys_and_forged_hash_rejected():
    with pytest.raises(ValueError):NS['parse_table']('{"table":["ALLOW","ALLOW"],"table":["DENY","DENY"]}',1)
    spec={'url':'https://raw.githubusercontent.com/o/r/'+'a'*40+'/a.txt','sha256':'f'*64}
    with pytest.raises(ValueError):NS['validate_source'](spec,{'url':spec['url'],'http':200,'status':'OK','hash':'f'*64,'body':'forged'})
