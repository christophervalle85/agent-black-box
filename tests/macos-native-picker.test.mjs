import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessMacSyntheticPicker} from '../examples/mcp-macos-native-picker.mjs';

const approved=Object.freeze({
  status:0,signal:null,error:null,stdout:'BBX_MAC_PICKER_EXACT_FIXTURE_SELECTED\n',
  stderr:''
});
const cancelled=Object.freeze({
  status:83,signal:null,error:null,stdout:'BBX_MAC_PICKER_USER_CANCELLED\n',
  stderr:''
});
test('native panel acceptance distinguishes exactly selected and explicitly cancelled',()=>{
  assert.equal(assessMacSyntheticPicker('select',approved),true);
  assert.equal(assessMacSyntheticPicker('cancel',cancelled),true);
  assert.throws(()=>assessMacSyntheticPicker('select',cancelled));
  assert.throws(()=>assessMacSyntheticPicker('cancel',approved));
  for(const bad of [
    {...approved,status:87},
    {...approved,stdout:'BBX_MAC_PICKER_OUTSIDE_FIXTURE\n'},
    {...approved,stdout:approved.stdout+'extra\n'},
    {...approved,stdout:'BBX_MAC_PICKER_EXACT_FIXTURE_SELECTED /Users/sensitive\n'},
    {...approved,stderr:'some native stderr\n'},
    {...approved,signal:'SIGKILL'},
    {...approved,error:new Error('process failed')},
    {...cancelled,status:85},
    {...cancelled,stdout:'BBX_MAC_PICKER_UNEXPECTED_SELECTION\n',status:86},
    {...cancelled,stdout:'BBX_MAC_PICKER_INVALID_FIXTURE\n',status:90},
    {status:null,stdout:'',stderr:''}
  ]){
    assert.throws(()=>assessMacSyntheticPicker('select',bad));
    assert.throws(()=>assessMacSyntheticPicker('cancel',bad));
  }
  assert.throws(()=>assessMacSyntheticPicker('approve',approved));
});
test('native panel fixture never reads files and checks the chosen path against a staged test fixture',()=>{
  const native=readFileSync(new URL('../native/macos/SyntheticOpenPanel.m',import.meta.url),'utf8');
  const cli=readFileSync(new URL('../examples/mcp-macos-native-picker.mjs',import.meta.url),'utf8');
  assert.match(native,/#import <AppKit\/AppKit.h>/);
  assert.match(native,/NSOpenPanel \*panel=\[NSOpenPanel openPanel\]/);
  assert.match(native,/NSModalResponseCancel/);
  assert.match(native,/panel\.canChooseDirectories=NO/);
  assert.match(native,/panel\.allowsMultipleSelection=NO/);
  assert.match(native,/panel\.resolvesAliases=NO/);
  assert.match(native,/lstat\(path,&details\)/);
  assert.match(native,/S_ISREG\(details\.st_mode\)/);
  assert.match(native,/details\.st_nlink!=1/);
  assert.match(native,/strcmp\(selected\.fileSystemRepresentation,fixture\.fileSystemRepresentation\)/);
  assert.match(native,/BBX_MAC_PICKER_OUTSIDE_FIXTURE/);
  assert.doesNotMatch(native,/\b(?:open|fopen|read|fread|system|popen)\s*\(/);
  assert.match(cli,/process\.platform!=='darwin'/);
  assert.match(cli,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(cli,/--verify','--strict'/);
  assert.match(cli,/writeFileSync\(file,'BBX synthetic picker fixture'/);
  assert.match(cli,/rmSync\(temp,\{recursive:true,force:true\}\)/);
  assert.doesNotMatch(cli,/createBlackBoxServer|createAuditedMacTransferController/);
});
