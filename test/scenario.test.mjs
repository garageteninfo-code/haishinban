// サンプルの台本を通しで回す（.NET 10 の SDK があれば C# の UpdateSafetyKit でも確かめる。無ければその部分は飛ばす）。
import assert from 'node:assert/strict';
import test from 'node:test';
import { runScenario } from '../scenario/sample-scenario.mjs';

test('サンプルの台本：10% で配る → 落ちる → 断る → 止める → C# が 1.1.0 を出さない', { timeout: 180000 }, async () => {
  const lines = [];
  const r = await runScenario({ log: (s) => lines.push(s) });
  const failed = r.checks.filter((c) => !c.ok).map((c) => c.name);
  console.log(`  台本: ${r.passed} / ${r.total} 合格・C# で確かめた: ${r.csharp ? 'はい（.NET ' + r.csharpRuntime + '）' : 'いいえ（SDK なし）'}`);
  assert.deepEqual(failed, []);
});
