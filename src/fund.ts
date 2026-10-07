import { createHash } from 'crypto';
import { Abi, Contract, ProviderInterface, Transaction, utils } from 'koilib';
import tokenAbi from './abis/token.json';

export interface FundContext {
  networkName: string;
  rpc: string;
  definition: { chainId?: string };
  contracts: { fund?: string; koin?: string; vhp?: string };
}

export interface FundProject {
  id: number;
  creator: string;
  beneficiary: string;
  title: string;
  description: string;
  monthly_payment: string;
  start_date: string;
  end_date: string;
  status: number;
  total_votes: string;
  votes: string[];
}

export interface FundVote {
  project_id: number;
  weight: number;
  expiration: string;
}

export interface FundGlobals {
  fee_denominator: string;
  total_projects: number;
  total_upcoming_projects: number;
  total_active_projects: number;
  payment_times: string[];
  remaining_balance: string;
}

export const PROJECT_STATUSES: Record<string, number> = { upcoming: 0, active: 1, past: 2 };

const METHODS: Record<string, { argument: string; result: string; readOnly: boolean }> = {
  get_global_vars: { argument: '', result: 'fund.global_vars', readOnly: true },
  get_project: { argument: 'fund.get_project_arguments', result: 'fund.project', readOnly: true },
  get_projects: { argument: 'fund.get_projects_arguments', result: 'fund.get_projects_result', readOnly: true },
  get_user_votes: { argument: 'fund.get_user_votes_arguments', result: 'fund.get_user_votes_result', readOnly: true },
  update_vote: { argument: 'fund.update_vote_arguments', result: 'fund.update_vote_result', readOnly: false },
};

export function methodEntryPoint(name: string): number {
  return parseInt(createHash('sha256').update(name).digest('hex').slice(0, 8), 16);
}

export function parseProjectId(value: string): number {
  if (!/^[1-9]\d*$/.test(value) || BigInt(value) > 4294967295n) {
    throw new Error('Project ID must be a positive uint32 integer.');
  }
  return Number(value);
}

export function parsePercentage(value: string): number {
  if (!/^\d+$/.test(value) || Number(value) > 100 || Number(value) % 5 !== 0) {
    throw new Error('Vote percentage must be an integer from 0 to 100 in steps of 5.');
  }
  return Number(value);
}

export function parsePositiveInteger(value: string, label: string, max: number): number {
  if (!/^[1-9]\d*$/.test(value) || BigInt(value) > BigInt(max)) {
    throw new Error(`${label} must be an integer from 1 to ${max}.`);
  }
  return Number(value);
}

export function unsigned(value: string): bigint {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) throw new Error('Invalid unsigned contract value.');
  return BigInt(value);
}

export function formatFundVotes(value: string): string {
  // Contract totals use twenty weight units per token; retain fractional base units.
  return utils.formatUnits((unsigned(value) * 5n).toString(), 10);
}

export function timestampIso(value: string): string {
  const timestamp = unsigned(value);
  if (timestamp > 8640000000000000n) throw new Error('Contract timestamp is outside the supported date range.');
  return new Date(Number(timestamp)).toISOString();
}

export function terminalText(value: string): string {
  return value.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');
}

export async function assertFundNetwork(context: FundContext, provider: ProviderInterface): Promise<void> {
  if (!context.definition.chainId) throw new Error(`No expected chain ID configured for ${context.networkName}.`);
  if (await provider.getChainId() !== context.definition.chainId) {
    throw new Error(`RPC chain ID does not match ${context.networkName}. Refusing to continue.`);
  }
}

interface SchemaField {
  type: string;
  id: number;
  rule?: string;
  options?: Record<string, unknown>;
}

// Validate the interface from chain metadata before allowing it to encode operations.
export function validateFundAbi(abi: Abi): Abi {
  for (const [name, expected] of Object.entries(METHODS)) {
    const method = abi?.methods?.[name];
    if (!method || method.entry_point !== methodEntryPoint(name)
      || (method.argument || '') !== expected.argument || (method.return || '') !== expected.result
      || method.read_only !== expected.readOnly) {
      throw new Error(`Incompatible fund ABI method: ${name}.`);
    }
  }
  const validated: Abi = structuredClone(abi);
  const schema = (validated.koilib_types as unknown as {
    nested?: { fund?: { nested?: Record<string, { fields?: Record<string, SchemaField>; values?: Record<string, number> }> } };
  })?.nested?.fund?.nested;
  const fields: Record<string, Record<string, [number, string, string?]>> = {
    get_project_arguments: { project_id: [1, 'uint32'] },
    get_user_votes_arguments: { voter: [1, 'bytes'] },
    update_vote_arguments: { voter: [1, 'bytes'], project_id: [2, 'uint32'], weight: [3, 'uint32'] },
    get_projects_arguments: {
      status: [1, 'project_status'], order_by: [2, 'order_projects_by'],
      start: [3, 'string'], limit: [4, 'int32'], descending: [5, 'bool'],
    },
    get_projects_result: { projects: [1, 'project', 'repeated'], start_next_page: [2, 'string'] },
    get_user_votes_result: { votes: [1, 'vote_info', 'repeated'] },
    vote_info: { project_id: [1, 'uint32'], weight: [2, 'uint32'], expiration: [3, 'uint64'] },
    project: {
      id: [1, 'uint32'], creator: [2, 'bytes'], beneficiary: [3, 'bytes'], title: [4, 'string'],
      description: [5, 'string'], monthly_payment: [6, 'uint64'], start_date: [7, 'uint64'],
      end_date: [8, 'uint64'], status: [9, 'project_status'], total_votes: [10, 'uint64'],
      votes: [11, 'uint64', 'repeated'],
    },
    global_vars: {
      fee_denominator: [1, 'uint64'], total_projects: [2, 'uint32'], total_upcoming_projects: [3, 'uint32'],
      total_active_projects: [4, 'uint32'], payment_times: [5, 'uint64', 'repeated'], remaining_balance: [6, 'uint64'],
    },
  };
  for (const [type, expected] of Object.entries(fields)) {
    const actual = schema?.[type]?.fields;
    for (const [name, [id, fieldType, rule]] of Object.entries(expected)) {
      const field = actual?.[name];
      if (!field || field.id !== id || field.type !== fieldType || field.rule !== rule
        || (fieldType === 'uint64' && field.options?.jstype !== undefined && field.options.jstype !== 'JS_STRING')
        || (fieldType === 'bytes' && field.options?.['(koinos.btype)'] !== undefined && field.options['(koinos.btype)'] !== 'ADDRESS')) {
        throw new Error(`Incompatible fund ABI field: ${type}.${name}.`);
      }
      // Deployed metadata omits display annotations; the wire fields remain identical.
      if (fieldType === 'uint64') field.options = { ...field.options, jstype: 'JS_STRING' };
      if (fieldType === 'bytes') field.options = { ...field.options, '(koinos.btype)': 'ADDRESS' };
    }
    if (type === 'update_vote_arguments' && Object.keys(actual!).length !== 3) {
      throw new Error('Incompatible fund vote argument schema.');
    }
  }
  for (const [type, expected] of Object.entries({ project_status: PROJECT_STATUSES, order_projects_by: { by_date: 0, by_votes: 1 } })) {
    for (const [name, value] of Object.entries(expected)) {
      if (schema?.[type]?.values?.[name] !== value) throw new Error(`Incompatible fund ABI enum: ${type}.${name}.`);
    }
  }
  return { ...validated, methods: Object.fromEntries(Object.entries(METHODS).map(([name, method]) => [name, {
    entry_point: methodEntryPoint(name), argument: method.argument, return: method.result, read_only: method.readOnly,
  }])) };
}

export function validateVoteChange(votes: FundVote[], project: FundProject, percent: number, balance: bigint) {
  parsePercentage(String(percent));
  const ids = new Set<number>();
  for (const vote of votes) {
    if (!Number.isInteger(vote.weight) || vote.weight < 1 || vote.weight > 20 || ids.has(vote.project_id)) {
      throw new Error('Invalid existing vote allocations returned by the fund.');
    }
    ids.add(vote.project_id);
  }
  const previous = votes.find(vote => vote.project_id === project.id);
  if (percent === 0 && !previous) throw new Error('No vote is recorded for this project.');
  if (project.status === 2 && (percent !== 0 || !previous)) {
    throw new Error('Past projects only allow removing an existing vote.');
  }
  if (![0, 1, 2].includes(project.status)) throw new Error('Unsupported project status.');
  if (project.status !== 2 && balance <= 0n) throw new Error('Voting requires a positive KOIN or VHP balance.');
  const usedWeight = votes.reduce((sum, vote) => sum + vote.weight, 0);
  const newWeight = percent / 5;
  const totalWeight = usedWeight - (previous?.weight || 0) + newWeight;
  if (totalWeight > 20) throw new Error(`Vote allocations would total ${totalWeight * 5}%, exceeding 100%. Remove or reduce another vote first.`);
  return { previous, newWeight, totalWeight, usedWeight };
}

export class FundClient {
  private constructor(public readonly contract: Contract, public readonly context: FundContext, private readonly provider: ProviderInterface) {}

  static async connect(context: FundContext, provider: ProviderInterface, override?: string): Promise<FundClient> {
    const id = override || context.contracts.fund;
    if (!id) throw new Error(`No verified fund contract configured for ${context.networkName}. Use --fund-contract with a verified deployment.`);
    if (!utils.isChecksumAddress(id)) throw new Error('Invalid fund contract address.');
    await assertFundNetwork(context, provider);
    const contract = new Contract({ id, provider });
    const abi = await contract.fetchAbi({ updateFunctions: false, updateSerializer: false });
    if (!abi) throw new Error('The fund contract has no ABI in chain metadata.');
    return new FundClient(new Contract({ id, provider, abi: validateFundAbi(abi) }), context, provider);
  }

  async globals(): Promise<FundGlobals> {
    const { result } = await this.contract.functions.get_global_vars<Partial<FundGlobals>>({});
    return {
      fee_denominator: result?.fee_denominator || '0', total_projects: result?.total_projects || 0,
      total_upcoming_projects: result?.total_upcoming_projects || 0, total_active_projects: result?.total_active_projects || 0,
      payment_times: result?.payment_times || [], remaining_balance: result?.remaining_balance || '0',
    };
  }

  async project(id: number): Promise<FundProject> {
    const { result } = await this.contract.functions.get_project<FundProject>({ project_id: id });
    if (result?.id !== id) throw new Error('Project was not found or returned an inconsistent ID.');
    return this.normalizeProject(result);
  }

  private normalizeProject(project: FundProject): FundProject {
    return { ...project, status: project.status ?? 0, votes: project.votes || [], total_votes: project.total_votes || '0', monthly_payment: project.monthly_payment || '0', start_date: project.start_date || '0', end_date: project.end_date || '0' };
  }

  async votes(address: string): Promise<FundVote[]> {
    if (!utils.isChecksumAddress(address)) throw new Error('Invalid voter address.');
    const { result } = await this.contract.functions.get_user_votes<{ votes?: FundVote[] }>({ voter: address });
    return result?.votes || [];
  }

  async projects(options: { status: string; order: string; limit: number; descending: boolean; all?: boolean; cursor?: string }) {
    if (!Object.prototype.hasOwnProperty.call(PROJECT_STATUSES, options.status)) throw new Error('Status must be active, upcoming, or past.');
    if (!['date', 'votes'].includes(options.order)) throw new Error('Order must be date or votes.');
    if (options.status === 'past' && options.order === 'votes') throw new Error('Past projects can only be ordered by date.');
    parsePositiveInteger(String(options.limit), 'Page limit', 100);
    // Fund indexes use encoded numeric string keys, up to 20 amount/date digits plus 7 ID digits.
    let cursor = options.cursor ?? (options.descending ? '9'.repeat(27) : '0');
    const seen = new Set<string>();
    const projects: FundProject[] = [];
    for (let page = 0; page < 1000; page++) {
      seen.add(cursor);
      const { result } = await this.contract.functions.get_projects<{ projects?: FundProject[]; start_next_page?: string }>({
        status: PROJECT_STATUSES[options.status], order_by: options.order === 'votes' ? 1 : 0,
        start: cursor, limit: options.limit, descending: options.descending,
      });
      const items = result?.projects || [];
      projects.push(...items.map(project => this.normalizeProject(project)));
      const next = result?.start_next_page;
      if (items.length === 0) return { projects };
      if (!next || seen.has(next)) throw new Error('Fund pagination returned a missing or repeated cursor.');
      if (items.length < options.limit) return { projects };
      if (!options.all) return { projects, nextCursor: next };
      cursor = next;
    }
    throw new Error('Fund pagination exceeded 1000 pages. Request a bounded page instead.');
  }

  async balances(address: string): Promise<{ koin: string; vhp: string }> {
    const read = async (id: string | undefined): Promise<string> => {
      if (!id) throw new Error('Network token contract is not configured.');
      const token = new Contract({ id, provider: this.provider, abi: tokenAbi });
      const { result } = await token.functions.balance_of<{ value: string }>({ owner: address });
      return result?.value || '0';
    };
    const koin = await read(this.context.contracts.koin);
    const vhp = await read(this.context.contracts.vhp);
    return { koin, vhp };
  }

  async prepareVote(id: number, percent: number, voter: string, requestedRcLimit?: string) {
    const project = await this.project(id);
    const votes = await this.votes(voter);
    const balances = await this.balances(voter);
    const allocation = validateVoteChange(votes, project, percent, unsigned(balances.koin) + unsigned(balances.vhp));
    const availableMana = unsigned(await this.provider.getAccountRc(voter));
    if (availableMana === 0n) throw new Error('No available mana to pay for the vote transaction.');
    const rcLimit = requestedRcLimit === undefined ? (availableMana / 10n || 1n) : unsigned(requestedRcLimit);
    if (rcLimit === 0n || rcLimit > availableMana) throw new Error('RC limit must be positive and no greater than available mana.');
    const globals = await this.globals();
    const { operation } = await this.contract.functions.update_vote({ voter, project_id: id, weight: allocation.newWeight }, { onlyOperation: true });
    const transaction = new Transaction({ provider: this.provider, options: { payer: voter, rcLimit: rcLimit.toString() } });
    await transaction.pushOperation(operation);
    await transaction.prepare();
    if (transaction.transaction.header?.chain_id !== this.context.definition.chainId) throw new Error('Prepared transaction chain ID does not match the selected network.');
    return { transaction, project, votes, balances, allocation, availableMana: availableMana.toString(), expiration: globals.payment_times[5] };
  }
}
