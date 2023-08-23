import threading
import time
from unittest import TestCase, main

from ecrterm.packets.context import enter_context, GlobalContext, CurrentContext


class TestContext(TestCase):
    def test_normal_access(self):
        GlobalContext['test_normal_access'] = 1

        self.assertEqual(1, GlobalContext['test_normal_access'])

        del GlobalContext['test_normal_access']

        self.assertRaises(KeyError, lambda: GlobalContext['test_normal_access'])

    def test_nested_access_1(self):
        GlobalContext['test_nested_access_1'] = 1

        with enter_context():
            self.assertEqual(1, CurrentContext['test_nested_access_1'])

            CurrentContext['test_nested_access_1'] = 2

            self.assertEqual(2, CurrentContext['test_nested_access_1'])

            del CurrentContext['test_nested_access_1']

            self.assertRaises(KeyError, lambda: CurrentContext['test_nested_access_1'])

        self.assertEqual(1, CurrentContext['test_nested_access_1'])

    def test_nested_access_2(self):
        CurrentContext['test_nested_access_2'] = 1

        with enter_context(test_nested_access_2=2):
            self.assertEqual(2, CurrentContext['test_nested_access_2'])

            with enter_context():
                self.assertEqual(2, CurrentContext['test_nested_access_2'])

                CurrentContext['test_nested_access_2'] = 3

                self.assertEqual(3, CurrentContext['test_nested_access_2'])

            self.assertEqual(2, CurrentContext['test_nested_access_2'])

    def test_nested_delete(self):
        CurrentContext['test_nested_delete'] = 1

        with enter_context():
            del CurrentContext['test_nested_delete']

            self.assertRaises(KeyError, lambda: CurrentContext['test_nested_delete'])

            CurrentContext['test_nested_delete'] = 2

            self.assertEqual(2, CurrentContext['test_nested_delete'])

        self.assertEqual(1, CurrentContext['test_nested_delete'])

    def test_nested_access_3(self):
        self.assertRaises(KeyError, lambda: CurrentContext['test_nested_access_3'])

        with enter_context():
            self.assertRaises(KeyError, lambda: CurrentContext['test_nested_access_3'])

            GlobalContext['test_nested_access_3'] = 1

            self.assertEqual(1, CurrentContext['test_nested_access_3'])

        self.assertEqual(1, CurrentContext['test_nested_access_3'])

    def test_threads(self):
        GlobalContext['test_threads'] = 1

        def test_fun(arg):
            self.assertEqual(1, CurrentContext['test_threads'])
            CurrentContext['test_threads'] = arg
            time.sleep(0.01)
            self.assertEqual(arg, CurrentContext['test_threads'])

        t1 = threading.Thread(target=lambda: test_fun(2))
        t2 = threading.Thread(target=lambda: test_fun(3))
        t3 = threading.Thread(target=lambda: test_fun(4))

        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()

        self.assertEqual(1, GlobalContext['test_threads'])
        self.assertEqual(1, CurrentContext['test_threads'])


if __name__ == '__main__':
    main()
