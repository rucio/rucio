import contextlib


class MockGfal2(object):
    files = {}

    class MockContext(object):
        def open(self, filename, mode='r'):
            return MockGfal2.files[filename]

    @staticmethod
    def creat_context():
        return MockGfal2.MockContext()


@contextlib.contextmanager
def mocked_gfal2(module, **configuration):
    for attr, value in configuration.items():
        setattr(MockGfal2, attr, value)

    setattr(module, 'gfal2', MockGfal2)
    try:
        yield
    finally:
        delattr(module, 'gfal2')
