import json
import unittest
from pathlib import Path

from yamldb.validation import ValidationError, load_schemas, load_yaml, validate_document
from yamldb.validation import validate_snapshot


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / 'yamldb' / 'schemas' / 'collections.yaml'


class ValidationTests(unittest.TestCase):
    def test_aliases_are_rejected_without_relying_on_an_unrelated_schema_error(self):
        for payload in (
            b'first: &shared value\nsecond: *shared\n',
            b'items: &items [*items]\n',
            b'first: &shared {key: value}\nsecond: *shared\n',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValidationError):
                    load_yaml(payload, 'alias fixture')

    def test_note_metadata_is_optional_nullable_and_type_checked(self):
        schemas = load_schemas(SCHEMA)
        document = {
            'schema_version': 1, 'kind': 'note', 'id': 'example',
            'title': 'Example', 'body': 'A synthetic note.',
        }
        validate_document(json.dumps(document).encode(), 'notes', 'example', schemas)
        for metadata in (None, {}, {'audience': 'developers'}):
            with self.subTest(metadata=metadata):
                validate_document(
                    json.dumps({**document, 'metadata': metadata}).encode(),
                    'notes', 'example', schemas,
                )
        for metadata in ('not a mapping', [], 3, False):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValidationError):
                    validate_document(
                        json.dumps({**document, 'metadata': metadata}).encode(),
                        'notes', 'example', schemas,
                    )

    def test_bundled_examples_validate(self):
        stats = validate_snapshot(ROOT / 'examples' / 'data', SCHEMA)
        self.assertEqual((stats.collections, stats.documents), (1, 1))
        schemas = load_schemas(SCHEMA)
        validate_document(
            (ROOT / 'examples' / 'second.yaml').read_bytes(),
            'notes', 'second', schemas,
        )


if __name__ == '__main__':
    unittest.main()
