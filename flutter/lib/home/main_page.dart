import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'components/secret_item.dart';
import 'model/secret.dart';
import 'provider/secret_list.dart';

import 'package:authenticator/ffi/ffi.dart';

class MainPage extends StatefulWidget {
  const MainPage({super.key});

  final String title = "身份验证器";

  @override
  State<MainPage> createState() => _MainPageState();
}

class _MainPageState extends State<MainPage>
    with SingleTickerProviderStateMixin {
  SecretListProvider provider = SecretListProvider();

  final Map<int, AnimationController> _aniController = {};
  final ScrollController _scrollController = ScrollController();
  bool _loadingMore = false;

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

  @override
  void initState() {
    _scrollController.addListener(_onScroll);
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadMore();
    });
    Api.hello().then((value) {
      print("ffi: {$value}");
      name = value;
      setState(() {});
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
            // Here we take the value from the MyHomePage object that was created by
            // the App.build method, and use it to set our appbar title.
            title: Text(widget.title),
          ),
          body: Padding(
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
            child: ListView.separated(
                controller: _scrollController,
                itemCount: provider.length() + 1,
                separatorBuilder: (context, _) {
                  return const Divider();
                },
                itemBuilder: (context, index) {
                  print(
                      "itemBuilder index: $index, length: ${provider.length()}");
                  if (index >= provider.length()) {
                    return const SizedBox(
                      height: 10,
                    );
                  } else {
                    return SecretItem(index, getController(context, index));
                  }
                }),
          ),
          floatingActionButton: FloatingActionButton(
            onPressed: _incrementCounter,
            tooltip: name,
            child: const Icon(Icons.add),
          ),
        ));
  }
}
