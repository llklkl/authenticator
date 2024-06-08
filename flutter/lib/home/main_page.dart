import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'components/secret_item.dart';
import 'components/fab.dart';
import 'model/secret.dart';
import 'provider/secret_list.dart';

import 'package:authenticator/src/rust/api/api.dart' as api;

class MainPage extends StatefulWidget {
  const MainPage({super.key});

  final String title = "身份验证器";

  @override
  State<MainPage> createState() => _MainPageState();
}

class _MainPageState extends State<MainPage> with TickerProviderStateMixin {
  SecretListProvider provider = SecretListProvider();

  final Map<int, AnimationController> _aniController = {};
  final ScrollController _scrollController = ScrollController();

  bool _loadingMore = false;
  // 是否显示遮罩层
  bool _showModalBarrier = false;

  String name = "";

  void _incrementCounter() {
    setState(() {
      provider.add(Secret(
          otpType: 1,
          algorithm: 1,
          label: "test",
          issuer: "llklkl",
          period: 5));
    });
  }

  AnimationController getController(BuildContext context, int index) {
    var secret =
        Provider.of<SecretListProvider>(context, listen: false).get(index);
    if (!_aniController.containsKey(secret.period)) {
      _aniController[secret.period] = AnimationController(
          vsync: this, duration: Duration(seconds: secret.period))
        ..repeat(reverse: false);
    }

    return _aniController[secret.period]!;
  }

  void _loadMore() async {
    setState(() {
      _loadingMore = true;
    });
    provider.load().then((_) {
      setState(() {
        _loadingMore = false;
      });
    });
  }

  void _onScroll() {
    if (_scrollController.position.pixels ==
        _scrollController.position.maxScrollExtent) {
      if (_loadingMore) {
        return;
      }

      _loadMore();
    }
  }

  void _onFabPressed() {
    setState(() {
      _showModalBarrier = !_showModalBarrier;
    });
  }

  @override
  void initState() {
    _scrollController.addListener(_onScroll);
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadMore();
    });
    setState(() {
      name = api.appinfo(name: "");
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    provider.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<SecretListProvider>.value(
        value: provider,
        child: Scaffold(
          appBar: AppBar(
            title: Text(widget.title),
          ),
          body: Stack(alignment: Alignment.topLeft, children: [
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
              child: ListView.separated(
                  controller: _scrollController,
                  itemCount: provider.length() + 1,
                  separatorBuilder: (context, _) {
                    return const Divider();
                  },
                  itemBuilder: (context, index) {
                    if (index >= provider.length()) {
                      return const SizedBox(
                        height: 10,
                      );
                    } else {
                      return SecretItem(index, getController(context, index));
                    }
                  }),
            ),
            const Fab(children: [
              ActionButton(icon: Icon(Icons.camera), tips: Text("扫描1")),
              ActionButton(icon: Icon(Icons.camera), tips: Text("扫描2")),
              ActionButton(icon: Icon(Icons.camera), tips: Text("扫描3")),
            ]),
          ]),
          drawer: Drawer(
            child: ListView(children: const [
              ListTile(
                title: Text("同步"),
              )
            ]),
          ),
        ));
  }
}
