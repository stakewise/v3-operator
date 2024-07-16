import json
import logging
import os
import subprocess  # nosec

from src.common.clients import consensus_client
from src.config.settings import settings

logger = logging.getLogger(__name__)

SLOTS_PER_HISTORICAL_ROOT = 8192


class ProofsGenerationWrapper:
    # todo: use tempfile?

    def __init__(self, slot: int, chain_id: int):
        self.slot = slot
        self.chain_id = chain_id

        self.files: set[str] = set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for file in self.files:
            self._cleanup_file(file)

    async def generate_withdrawal_credentials(self, validator_index: int) -> dict:
        '''
        $ ./generation/generation \
        -command ValidatorFieldsProof \
        -oracleBlockHeaderFile [ORACLE_BLOCK_HEADER_FILE_PATH] \
        -stateFile [STATE_FILE_PATH] \
        -validatorIndex [VALIDATOR_INDEX] \
        -outputFile [OUTPUT_FILE_PATH] \
        -chainID [CHAIN_ID]
        '''

        block_header_file = await self._prepare_block_header_file(self.slot)
        state_data_file = await self._prepare_state_data_file(self.slot)
        self.files.update([block_header_file, state_data_file])
        output_filename = f'tmp_withdrawal_credentials_output_{validator_index}_{self.slot}'
        args = [
            'bin/generation',
            '-command',
            'ValidatorFieldsProof',
            '-oracleBlockHeaderFile',
            block_header_file,
            '-stateFile',
            state_data_file,
            '-validatorIndex',
            str(validator_index),
            '-outputFile',
            output_filename,
            '-chainID',
            str(self.chain_id),
        ]
        result = subprocess.run(args, capture_output=True, shell=False, check=False)  # nosec
        if result.stdout:
            logger.debug(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)

        with open(output_filename, 'r', encoding='utf-8') as file:
            data = json.load(file)

        with open(state_data_file, 'r', encoding='utf-8') as file:
            state_data = json.load(file)
            data['oracleTimestamp'] = (
                state_data.get('data', {}).get('latest_execution_payload_header').get('timestamp')
            )
        self._cleanup_file(output_filename)
        return data

    # pylint: disable-next=too-many-locals
    async def generate_withdrawal_fields_proof(
        self, withdrawals_slot: int, validator_index: int, withdrawal_index: int
    ) -> dict:
        '''
          -command WithdrawalFieldsProof \
          -oracleBlockHeaderFile [ORACLE_BLOCK_HEADER_FILE_PATH] \
          -stateFile [STATE_FILE_PATH] \
          -validatorIndex [VALIDATOR_INDEX] \
          -outputFile [OUTPUT_FILE_PATH] \
          -chainID [CHAIN_ID] \
          -historicalSummariesIndex [HISTORICAL_SUMMARIES_INDEX] \
          -blockHeaderIndex [BLOCK_HEADER_INDEX] \
          -historicalSummaryStateFile [HISTORICAL_SUMMARY_STATE_FILE_PATH] \
          -blockHeaderFile [BLOCK_HEADER_FILE_PATH] \
          -blockBodyFile [BLOCK_BODY_FILE_PATH] \
          -withdrawalIndex [WITHDRAWAL_INDEX]
        '''
        oracle_block_header_file = await self._prepare_block_header_file(self.slot)
        state_data_file = await self._prepare_state_data_file(self.slot)
        self.files.update([oracle_block_header_file, state_data_file])

        historical_summaries_index = (
            withdrawals_slot - settings.network_config.SHAPELLA_SLOT
        ) // SLOTS_PER_HISTORICAL_ROOT

        # "historicalSummaryStateFile" This is the beacon state at the slot such that:
        # historical_summary_state_slot =
        #    SLOTS_PER_HISTORICAL_ROOT * ((withdrawal_slot // SLOTS_PER_HISTORICAL_ROOT) + 1).
        historical_summary_state_slot = self._get_historical_summary_state_slot(withdrawals_slot)
        historical_summary_state_file = await self._prepare_state_data_file(
            historical_summary_state_slot
        )

        # blockHeaderIndex this is the blockheaderRoot index within the historical summaries entry
        # which can be calculated like this: withdrawal_slot mod SLOTS_PER_HISTORICAL_ROOT
        block_header_index = withdrawals_slot % SLOTS_PER_HISTORICAL_ROOT

        block_header_file = await self._prepare_block_header_file(withdrawals_slot)
        block_body_file = await self._prepare_block_body_file(withdrawals_slot)
        output_filename = f'tmp_verify_withdrawal_fields_proof_output_{validator_index}_{self.slot}'
        args = [
            'bin/generation',
            '-command',
            'WithdrawalFieldsProof',
            '-oracleBlockHeaderFile',
            oracle_block_header_file,
            '-stateFile',
            state_data_file,
            '-validatorIndex',
            str(validator_index),
            '-outputFile',
            output_filename,
            '-chainID',
            str(self.chain_id),
            '-historicalSummariesIndex',
            str(historical_summaries_index),
            '-blockHeaderIndex',
            str(block_header_index),
            '-historicalSummaryStateFile',
            historical_summary_state_file,
            '-blockHeaderFile',
            block_header_file,
            '-blockBodyFile',
            block_body_file,
            '-withdrawalIndex',
            str(withdrawal_index),
        ]

        result = subprocess.run(args, capture_output=True, shell=False, check=False)  # nosec
        if result.stdout:
            logger.debug(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)

        with open(output_filename, 'r', encoding='utf-8') as file:
            data = json.load(file)
        with open(state_data_file, 'r', encoding='utf-8') as file:
            state_data = json.load(file)
            data['oracleTimestamp'] = (
                state_data.get('data', {}).get('latest_execution_payload_header').get('timestamp')
            )
        self._cleanup_file(output_filename)
        return data

    def cleanup_withdrawals_slot_files(self, slot: int) -> None:
        historical_summary_state_slot = self._get_historical_summary_state_slot(slot)
        self._cleanup_file(self.get_state_data_filename(historical_summary_state_slot))
        self._cleanup_file(self.get_block_header_filename(slot))
        self._cleanup_file(self.get_block_body_filename(slot))

    def get_block_header_filename(self, slot: int) -> str:
        return f'tmp_block_header_{slot}.json'

    def get_block_body_filename(self, slot: int) -> str:
        return f'tmp_block_body_{slot}.json'

    def get_state_data_filename(self, slot: int) -> str:
        return f'tmp_slot_{slot}.json'

    async def _prepare_block_header_file(self, slot: int) -> str:
        filename = self.get_block_header_filename(slot)
        if os.path.isfile(filename):
            return filename

        block_header_data = await consensus_client.get_block_header(str(slot))
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(block_header_data, file)
        return filename

    async def _prepare_block_body_file(self, slot: int) -> str:
        block_data = await consensus_client.get_block(str(slot))
        filename = self.get_block_body_filename(slot)
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(block_data, file)
        return filename

    async def _prepare_state_data_file(self, slot: int) -> str:
        filename = self.get_state_data_filename(slot)
        if os.path.isfile(filename):
            return filename

        state_data = await consensus_client.get_beacon_state(str(slot))
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(state_data, file)
        return filename

    def _cleanup_file(self, filename: str) -> None:
        os.remove(filename)

    def _get_historical_summary_state_slot(self, slot: int) -> int:
        return SLOTS_PER_HISTORICAL_ROOT * ((slot // SLOTS_PER_HISTORICAL_ROOT) + 1)
