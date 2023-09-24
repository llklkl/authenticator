import 'package:authenticator/home/components/secret_item.dart';
import 'package:authenticator/home/provider/secret_list.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

class SecretList extends StatefulWidget {
  const SecretList({super.key});

  @override
  State<SecretList> createState() => _SecretListState();
}

class _SecretListState extends State<SecretList>
    with SingleTickerProviderStateMixin {
  final Map<int, AnimationController> _aniController = {};
  final ScrollController _scrollController = ScrollController();
  bool _loadingMore = false;

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

  Future _loadMore() async {
    return Provider.of<SecretListProvider>(context, listen: false).load();
  }

  void _onScroll() async {
    if (_scrollController.position.pixels ==
        _scrollController.position.maxScrollExtent) {
      if (_loadingMore) {
        return;
      }

      setState(() {
        _loadingMore = true;
      });

      await _loadMore();
      setState(() {
        _loadingMore = false;
      });
    }
  }

  @override
  void initState() {
    _scrollController.addListener(_onScroll);

    super.initState();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<SecretListProvider>(builder: (context, provider, child) {
      return ListView.separated(
          controller: _scrollController,
          itemCount: provider.length()+1,
          separatorBuilder: (context, _) {
            return const Divider();
          },
          itemBuilder: (context, index) {
            return SecretItem(index, getController(context, index));
          });
    });
  }
}
