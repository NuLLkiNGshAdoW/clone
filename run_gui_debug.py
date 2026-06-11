import traceback

try:
    import WifiSecuritySystem
    print('import ok')
    app = WifiSecuritySystem.SOCSentinel()
    print('app created')
    app.mainloop()
    print('mainloop ended')
except Exception:
    traceback.print_exc()
    raise
