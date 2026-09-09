import ctypes
import os

# ==========================================
# 1. 定义数据结构
# ==========================================
class PolitoWrapper(ctypes.Structure):
    _fields_ = [
        ('game', ctypes.c_void_p),
        ('market', ctypes.c_void_p),
        ('earned_money', ctypes.c_ulong), # 关键字段：已赚取的钱
    ]

class GameWrapper(ctypes.Structure):
    _fields_ = [
        ('lives', ctypes.c_int),
        ('money', ctypes.c_ulong),        # 关键字段：当前现金
    ]

class MarketElementWrapper(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_char_p),
        ('desc', ctypes.c_char_p),
        ('price', ctypes.c_ulong),
        ('bought', ctypes.c_bool)
    ]

class MarketWrapper(ctypes.Structure):
    _fields_ = [
        ('size', ctypes.c_int),
        ('elements', 7 * MarketElementWrapper),
    ]

# ==========================================
# 2. 执行逻辑
# ==========================================
def get_flag():
    # --- 加载库 ---
    lib_path = os.path.join(os.getcwd(), 'lib', 'libgame.so')
    try:
        clib = ctypes.CDLL(lib_path)
    except OSError as e:
        print(f"错误: 找不到库文件 {lib_path}")
        return

    # 设置函数签名
    clib.polito_init.restype = ctypes.c_void_p
    clib.polito_init.argtypes = []
    
    clib.market_buy.restype = ctypes.c_ubyte
    clib.market_buy.argtypes = [ctypes.POINTER(PolitoWrapper), ctypes.c_int]

    # --- 初始化 ---
    print("[1] 初始化游戏内存...")
    game_ptr_addr = clib.polito_init()
    polito = PolitoWrapper.from_address(game_ptr_addr)

    # --- 作弊 (关键步骤) ---
    print(f"[2] 当前资产: {polito.earned_money}。正在执行金钱修改作弊...")
    
    # 1. 修改 earned_money (绕过 'Freshman' 身份检查)
    polito.earned_money = 999999999
    
    # 2. 修改 money (确保买得起)
    game_struct = ctypes.cast(polito.game, ctypes.POINTER(GameWrapper)).contents
    game_struct.money = 999999999
    
    print(f"    -> 作弊成功！当前现金: {game_struct.money}, 总资产: {polito.earned_money}")

    # --- 购买第7个商品 (Index 6) ---
    print("[3] 尝试调用 market_buy 购买第 7 个神秘商品...")
    # 注意：这里需要传入 polito 结构的指针
    ret = clib.market_buy(ctypes.byref(polito), 6)

    if ret == 1:
        print("    -> 购买成功！C 库应该已经把 Flag 解密到内存里了。")
    elif ret == 2:
        print("    -> 提示：商品已购买。")
    else:
        print(f"    -> 购买失败 (返回码 {ret})。请检查作弊是否生效。")
        return

    # --- 再次读取内存获取 Flag ---
    print("[4] 读取商品描述...")
    market_ptr = ctypes.cast(polito.market, ctypes.POINTER(MarketWrapper))
    target_item = market_ptr.contents.elements[6]
    
    desc = target_item.desc.decode('utf-8', errors='ignore')
    
    print("\n" + "="*40)
    print(f"FLAG: {desc}")
    print("="*40 + "\n")

if __name__ == "__main__":
    get_flag()
    
#FLAG: ptm{p4tch1ng_3xecut4bl3s_1s_fun}