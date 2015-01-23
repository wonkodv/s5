if __name__ == '__main__':
    from .cli import main, parseArgs
    import sys
    o = parseArgs()
    ret = main(o)
    sys.exit(ret)
