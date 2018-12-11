from collections import Counter, deque, OrderedDict
import babeltrace
import sys

def to_hex(number):
    return '0x{:X}'.format(number)

class TCCoro:
    def __init__(self, event):
        if event is not None:
            self._init(event)


    def _init(self, event):
        self._begin = event.timestamp
        self._end = None
        self._msg = event['msg']
        self._type = event['type']
        self._id = event['coro_id']
        self._stack = event['coro_stack']
        self._children = deque()


    @property
    def duration(self):
        if self._end is None or self._begin is None:
            raise RuntimeError("invalid coro duration")
        return self._end - self._begin


    @property
    def id(self):
        return to_hex(self._id)


    @property
    def name(self):
        return self._msg


    def startChild(self, childCoro):
        self._children.append(childCoro)
        return childCoro


    def child(self, id):
        return self._children[id][-1]

    @property
    def lastChild(self):
        return self._children[-1]

    def endChild(self, event):
        id = event['coro_id']
        if event['type'] != self.lastChild._type:
            raise RuntimeError('type does not match')
        if event['msg'] != self.lastChild._msg:
            raise RuntimeError('msg does not match')
        if event['coro_stack'] != self.lastChild._stack:
            raise RuntimeError('stack does not match')
        self.lastChild.setEnd(event.timestamp)


    def setEnd(self, timestamp):
        if self._end is not None:
            raise RuntimeError('coro\'s {} end already been set'.format(self.id))
        self._end = timestamp

    @property
    def stackId(self):
        return self._stack

    def __hash__(self):
        return hash(self.id)


class TCStack:
    def __init__(self, event):
        if event is not None:
            self._init(event)


    def _init(self, event):
        self._id = event['coro_stack']
        self._children = deque()
        self._coro_stack = deque()


    @property
    def id(self):
        return to_hex(self._id)


    def addCoro(self, coro):
        if self._coro_stack and coro.stackId != self.current_coro.stackId:
            raise RuntimeError("coros {} and {} stack's id are different".format(event[msg], self.current_coro.name))
        self._coro_stack.append(coro)


    def startChild(self, event):
        coro = TCCoro(event)
        if self._coro_stack:
            self.current_coro.startChild(coro)
        else:
            self._children.append(coro)
        self.addCoro(coro)
        return coro



    def endChild(self, event):
        coro = self._coro_stack.pop()
        if self._coro_stack:
            self.current_coro.endChild(event)
        else:
            coro.setEnd(event.timestamp)
        return coro


    @property
    def current_coro(self):
        return self._coro_stack[-1]


    def __hash__(self):
        return hash(self.id)



def coro_parse(col):
    coro_stacks = OrderedDict()
    for event in col.events:
        if event.name == 'ttracer:coro_beacon':
            stack_id = event['coro_stack']
            if event['state'] == 'Begin':
                if stack_id not in coro_stacks:
                    coro_stacks[stack_id] = TCStack(event)
                child = coro_stacks[stack_id].startChild(event);
            elif event['state'] == 'End':
                if stack_id not in coro_stacks:
                    raise RuntimeError('invalid stack id {}'.format(stack_id))
                child = coro_stacks[stack_id].endChild(event)
    print("parse complete")
    return coro_stacks


def print_coro(stack, depth):
    for child in stack._children:
        print("{} {}, ts {}ms".format(' ' * depth, child.name, child.duration / 1e6))
        print_coro(child, depth + 1)


def print_stacks(stacks):
    for stack in stacks.values():
        print("stack, roots {}, id {}".format(len(stack._children), stack.id))
        print_coro(stack, 0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("tracepath missing")
        sys.exit(1)
    col = babeltrace.TraceCollection()
    if col.add_trace(sys.argv[1], 'ctf') is None:
        raise RuntimeError('Cannot add trace')

    stacks = coro_parse(col)
    print_stacks(stacks)
    sys.exit(0)
